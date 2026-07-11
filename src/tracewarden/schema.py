"""The ``security.event.*`` attribute schema.

tracewarden records each finding as an OTel *span event* named ``security.event``
with a flat, portable attribute namespace, plus per-span summary attributes so
backends without event-level querying (and simple TraceQL/SQL) can still filter.
Proposed as a semantic-convention extension; see docs/adr/0001.
"""

from __future__ import annotations

from enum import StrEnum

from opentelemetry.trace import Span
from pydantic import BaseModel, ConfigDict, Field

# Span event name for a single finding.
EVENT_NAME = "security.event"

# Attributes on the span event (one per finding).
ATTR_TYPE = "security.event.type"
ATTR_SEVERITY = "security.event.severity"
ATTR_CONFIDENCE = "security.event.confidence"
ATTR_DETECTOR = "security.event.detector"
ATTR_RULE = "security.event.rule"
ATTR_SURFACE = "security.event.surface"
ATTR_EVIDENCE = "security.event.evidence"

# Per-span summary attributes (aggregated over all findings on the span).
SPAN_EVENT_COUNT = "security.events.count"
SPAN_MAX_SEVERITY = "security.events.max_severity"
SPAN_EVENT_TYPES = "security.events.types"

AttributeValue = str | int | float | bool


class EventType(StrEnum):
    """Security event classes tracewarden can tag."""

    PROMPT_INJECTION = "prompt_injection"
    SECRET_LEAK = "secret_leak"  # noqa: S105 — enum value, not a credential
    PII_LEAK = "pii_leak"
    TOOL_POISONING = "tool_poisoning"
    SCOPE_VIOLATION = "scope_violation"
    MEMORY_POISONING = "memory_poisoning"
    ANOMALOUS_SEQUENCE = "anomalous_sequence"
    COST_ANOMALY = "cost_anomaly"
    LOOP_ANOMALY = "loop_anomaly"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Surface(StrEnum):
    """Where in the agent loop the flagged content was observed."""

    SYSTEM_PROMPT = "system_prompt"
    USER_PROMPT = "user_prompt"
    COMPLETION = "completion"
    TOOL_INPUT = "tool_input"
    TOOL_OUTPUT = "tool_output"
    MEMORY_WRITE = "memory_write"


def redact(match: str, keep: int = 2) -> str:
    """Mask a matched string for safe use as evidence: ``sk…89 (len=32)``.

    Never put raw matched content on a span — the trace backend must not become
    a second copy of the leak.
    """
    if len(match) <= keep * 2:
        return f"*** (len={len(match)})"
    return f"{match[:keep]}…{match[-keep:]} (len={len(match)})"


class SecurityEvent(BaseModel):
    """One security finding, attachable to any OTel span."""

    model_config = ConfigDict(frozen=True)

    type: EventType
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    detector: str
    rule: str
    surface: Surface
    evidence: str = ""

    def otel_attributes(self) -> dict[str, AttributeValue]:
        attrs: dict[str, AttributeValue] = {
            ATTR_TYPE: self.type.value,
            ATTR_SEVERITY: self.severity.value,
            ATTR_CONFIDENCE: self.confidence,
            ATTR_DETECTOR: self.detector,
            ATTR_RULE: self.rule,
            ATTR_SURFACE: self.surface.value,
        }
        if self.evidence:
            attrs[ATTR_EVIDENCE] = self.evidence
        return attrs


def record_events(span: Span, events: list[SecurityEvent]) -> None:
    """Attach findings to a span: one span event each, plus summary attributes."""
    if not events:
        return
    for event in events:
        span.add_event(EVENT_NAME, attributes=event.otel_attributes())
    span.set_attribute(SPAN_EVENT_COUNT, len(events))
    span.set_attribute(SPAN_MAX_SEVERITY, max(events, key=lambda e: e.severity.rank).severity.value)
    span.set_attribute(SPAN_EVENT_TYPES, sorted({e.type.value for e in events}))
