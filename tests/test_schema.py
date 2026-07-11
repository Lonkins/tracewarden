import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tracewarden.schema import (
    ATTR_SEVERITY,
    ATTR_TYPE,
    EVENT_NAME,
    SPAN_EVENT_COUNT,
    SPAN_EVENT_TYPES,
    SPAN_MAX_SEVERITY,
    EventType,
    SecurityEvent,
    Severity,
    Surface,
    record_events,
    redact,
)


def make_event(
    type_: EventType = EventType.SECRET_LEAK,
    severity: Severity = Severity.HIGH,
) -> SecurityEvent:
    return SecurityEvent(
        type=type_,
        severity=severity,
        detector="tracewarden.secrets",
        rule="aws_access_key_id",
        surface=Surface.COMPLETION,
        evidence="AK…XY (len=20)",
    )


def test_severity_ordering() -> None:
    ranks = [s.rank for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert ranks == sorted(ranks)
    assert Severity.CRITICAL.rank > Severity.HIGH.rank


def test_event_is_frozen() -> None:
    event = make_event()
    with pytest.raises(Exception):  # noqa: B017 — pydantic raises ValidationError on frozen
        event.severity = Severity.LOW  # type: ignore[misc]


def test_confidence_bounds() -> None:
    with pytest.raises(ValueError):
        SecurityEvent.model_validate(make_event().model_dump() | {"confidence": 1.5})


def test_otel_attributes_flat_and_typed() -> None:
    attrs = make_event().otel_attributes()
    assert attrs[ATTR_TYPE] == "secret_leak"
    assert attrs[ATTR_SEVERITY] == "high"
    assert all(isinstance(v, str | int | float | bool) for v in attrs.values())


def test_redact_masks_and_keeps_length() -> None:
    assert redact("AKIAIOSFODNN7EXAMPLE") == "AK…LE (len=20)"
    assert "shrt" not in redact("shrt")
    assert redact("abcd") == "*** (len=4)"


def test_record_events_adds_span_events_and_summary() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("test")

    with tracer.start_as_current_span("llm.call") as span:
        record_events(
            span,
            [
                make_event(),
                make_event(EventType.PROMPT_INJECTION, Severity.CRITICAL),
            ],
        )

    (span_data,) = exporter.get_finished_spans()
    events = [e for e in span_data.events if e.name == EVENT_NAME]
    assert len(events) == 2
    assert span_data.attributes is not None
    assert span_data.attributes[SPAN_EVENT_COUNT] == 2
    assert span_data.attributes[SPAN_MAX_SEVERITY] == "critical"
    assert tuple(span_data.attributes[SPAN_EVENT_TYPES]) == (  # type: ignore[arg-type]
        "prompt_injection",
        "secret_leak",
    )


def test_record_events_noop_on_empty() -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    with provider.get_tracer("test").start_as_current_span("x") as span:
        record_events(span, [])
    (span_data,) = exporter.get_finished_spans()
    assert span_data.attributes is not None
    assert SPAN_EVENT_COUNT not in span_data.attributes
