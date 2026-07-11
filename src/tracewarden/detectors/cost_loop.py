"""Cost/loop anomaly detector (stateful, per trace).

- ``llm_call_budget`` model calls in one trace → cost anomaly (runaway agent)
- the same prompt text scanned ≥ ``repeat_threshold`` times → loop anomaly
"""

from __future__ import annotations

from typing import Any, ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors._text import digest
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface

_STATE_KEY = "tracewarden.cost_loop"

_LLM_SURFACES = frozenset({Surface.USER_PROMPT, Surface.SYSTEM_PROMPT})


@register("cost_loop")
def _factory(config: TracewardenConfig) -> CostLoopDetector:
    return CostLoopDetector(
        llm_call_budget=config.llm_call_budget,
        repeat_threshold=config.repeat_threshold,
    )


class CostLoopDetector(Detector):
    id: ClassVar[str] = "tracewarden.cost_loop"
    toggle: ClassVar[str] = "cost_loop"

    def __init__(self, llm_call_budget: int = 25, repeat_threshold: int = 3) -> None:
        self.llm_call_budget = llm_call_budget
        self.repeat_threshold = repeat_threshold

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        if ctx.surface is not Surface.USER_PROMPT:
            return []
        state: dict[str, Any] = ctx.trace_state.setdefault(
            _STATE_KEY, {"llm_calls": 0, "prompts": {}, "flagged": set()}
        )
        state["llm_calls"] += 1
        prompt_key = digest(ctx.text)
        state["prompts"][prompt_key] = state["prompts"].get(prompt_key, 0) + 1

        findings: list[SecurityEvent] = []

        def add(event_type: EventType, rule: str, severity: Severity, evidence: str) -> None:
            if rule in state["flagged"]:
                return
            state["flagged"].add(rule)
            findings.append(
                SecurityEvent(
                    type=event_type,
                    severity=severity,
                    detector=self.id,
                    rule=rule,
                    surface=ctx.surface,
                    evidence=evidence,
                )
            )

        if state["llm_calls"] > self.llm_call_budget:
            add(
                EventType.COST_ANOMALY,
                "llm_call_budget_exceeded",
                Severity.HIGH,
                f"llm_calls={state['llm_calls']} budget={self.llm_call_budget}",
            )
        if state["prompts"][prompt_key] >= self.repeat_threshold:
            add(
                EventType.LOOP_ANOMALY,
                "repeated_identical_prompt",
                Severity.HIGH,
                f"repeats={state['prompts'][prompt_key]}",
            )
        return findings
