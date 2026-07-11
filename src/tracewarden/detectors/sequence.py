"""Anomalous tool-call sequence detector (stateful, per trace).

Flags, deterministically:
- the same tool called with identical input ≥ ``repeat_threshold`` times
- A→B→A→B ping-pong alternation over ≥ 2 full cycles
- tool fan-out: more distinct tools in one trace than ``tool_fanout_threshold``
"""

from __future__ import annotations

from typing import Any, ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors._text import digest
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface

_STATE_KEY = "tracewarden.sequence"


@register("anomalous_sequence")
def _factory(config: TracewardenConfig) -> SequenceDetector:
    return SequenceDetector(
        repeat_threshold=config.repeat_threshold,
        fanout_threshold=config.tool_fanout_threshold,
    )


class SequenceDetector(Detector):
    id: ClassVar[str] = "tracewarden.sequence"
    toggle: ClassVar[str] = "anomalous_sequence"

    def __init__(self, repeat_threshold: int = 3, fanout_threshold: int = 15) -> None:
        self.repeat_threshold = repeat_threshold
        self.fanout_threshold = fanout_threshold

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        if ctx.surface is not Surface.TOOL_INPUT or not ctx.tool_name:
            return []
        state: dict[str, Any] = ctx.trace_state.setdefault(
            _STATE_KEY, {"order": [], "calls": {}, "flagged": set()}
        )
        tool = ctx.tool_name
        call_key = f"{tool}:{digest(ctx.text)}"
        state["order"].append(tool)
        state["calls"][call_key] = state["calls"].get(call_key, 0) + 1

        findings: list[SecurityEvent] = []

        def add(rule: str, severity: Severity, evidence: str) -> None:
            if rule in state["flagged"]:
                return  # one event per anomaly class per trace, not per call
            state["flagged"].add(rule)
            findings.append(
                SecurityEvent(
                    type=EventType.ANOMALOUS_SEQUENCE,
                    severity=severity,
                    detector=self.id,
                    rule=rule,
                    surface=ctx.surface,
                    evidence=evidence,
                )
            )

        if state["calls"][call_key] >= self.repeat_threshold:
            add(
                "repeated_identical_call",
                Severity.MEDIUM,
                f"tool={tool} repeats={state['calls'][call_key]}",
            )

        order: list[str] = state["order"]
        if len(order) >= 4 and order[-4:] == [order[-2], order[-1]] * 2 and order[-1] != order[-2]:
            add(
                "tool_ping_pong",
                Severity.MEDIUM,
                f"pattern={order[-2]}->{order[-1]} x2",
            )

        distinct = len(set(order))
        if distinct > self.fanout_threshold:
            add("tool_fanout", Severity.MEDIUM, f"distinct_tools={distinct}")

        return findings
