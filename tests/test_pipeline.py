from typing import ClassVar

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Span

import tracewarden
from tracewarden.config import DetectorToggles, TracewardenConfig
from tracewarden.detectors.base import Detector, ScanContext, build_detectors, register
from tracewarden.pipeline import DetectionPipeline
from tracewarden.schema import (
    EVENT_NAME,
    SPAN_EVENT_COUNT,
    SPAN_MAX_SEVERITY,
    EventType,
    SecurityEvent,
    Severity,
    Surface,
)


class KeywordDetector(Detector):
    """Test detector: flags any text containing 'bomb'."""

    id: ClassVar[str] = "test.keyword"
    toggle: ClassVar[str] = "secrets"

    def __init__(self, severity: Severity = Severity.HIGH) -> None:
        self.severity = severity

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        if "bomb" not in ctx.text:
            return []
        return [
            SecurityEvent(
                type=EventType.PROMPT_INJECTION,
                severity=self.severity,
                detector=self.id,
                rule="keyword",
                surface=ctx.surface,
            )
        ]


class CountingDetector(Detector):
    """Test detector: uses trace_state to count scans per trace."""

    id: ClassVar[str] = "test.counter"
    toggle: ClassVar[str] = "cost_loop"

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        count = ctx.trace_state.get("test.counter", 0) + 1
        ctx.trace_state["test.counter"] = count
        if count < 3:
            return []
        return [
            SecurityEvent(
                type=EventType.LOOP_ANOMALY,
                severity=Severity.MEDIUM,
                detector=self.id,
                rule="three_scans",
                surface=ctx.surface,
            )
        ]


def make_provider() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def test_pipeline_attaches_events_and_summary() -> None:
    provider, exporter = make_provider()
    pipeline = DetectionPipeline([KeywordDetector()])
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("llm.call") as span:
        pipeline(span, Surface.USER_PROMPT, "how to defuse a bomb", {})
        pipeline(span, Surface.USER_PROMPT, "harmless", {})

    (span_data,) = exporter.get_finished_spans()
    events = [e for e in span_data.events if e.name == EVENT_NAME]
    assert len(events) == 1
    assert span_data.attributes is not None
    assert span_data.attributes[SPAN_EVENT_COUNT] == 1


def test_summary_accumulates_across_scans_on_same_span() -> None:
    provider, exporter = make_provider()
    pipeline = DetectionPipeline([KeywordDetector(Severity.LOW)])
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("llm.call") as span:
        pipeline(span, Surface.USER_PROMPT, "bomb one", {})
        pipeline(span, Surface.COMPLETION, "bomb two", {})

    (span_data,) = exporter.get_finished_spans()
    assert span_data.attributes is not None
    assert span_data.attributes[SPAN_EVENT_COUNT] == 2
    assert span_data.attributes[SPAN_MAX_SEVERITY] == "low"


def test_trace_state_shared_within_trace() -> None:
    provider, exporter = make_provider()
    pipeline = DetectionPipeline([CountingDetector()])
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("root"):
        for _ in range(3):
            with tracer.start_as_current_span("tool x") as span:
                pipeline(span, Surface.TOOL_INPUT, "text", {})

    flagged = [
        s
        for s in exporter.get_finished_spans()
        if s.attributes and s.attributes.get(SPAN_EVENT_COUNT)
    ]
    assert len(flagged) == 1  # only the third call in the same trace trips it


def test_trace_state_isolated_between_traces() -> None:
    provider, exporter = make_provider()
    pipeline = DetectionPipeline([CountingDetector()])
    tracer = provider.get_tracer("t")
    for _ in range(3):  # three separate traces — never reaches 3 in one
        with tracer.start_as_current_span("tool x") as span:
            pipeline(span, Surface.TOOL_INPUT, "text", {})

    flagged = [
        s
        for s in exporter.get_finished_spans()
        if s.attributes and s.attributes.get(SPAN_EVENT_COUNT)
    ]
    assert flagged == []


def test_on_events_callback_fires() -> None:
    provider, _ = make_provider()
    received: list[tuple[Span, int]] = []
    pipeline = DetectionPipeline(
        [KeywordDetector()], on_events=lambda span, evts: received.append((span, len(evts)))
    )
    with provider.get_tracer("t").start_as_current_span("s") as span:
        pipeline(span, Surface.USER_PROMPT, "bomb", {})
    assert received and received[0][1] == 1


def test_build_detectors_respects_toggles() -> None:
    from tracewarden.detectors import base

    saved = dict(base._REGISTRY)
    base._REGISTRY.clear()
    register("secrets")(lambda cfg: KeywordDetector())
    register("cost_loop")(lambda cfg: CountingDetector())
    try:
        on = TracewardenConfig(detectors=DetectorToggles(secrets=True, cost_loop=False))
        built = build_detectors(on)
        assert [type(d) for d in built] == [KeywordDetector]
    finally:
        base._REGISTRY.clear()
        base._REGISTRY.update(saved)


def test_install_registers_pipeline_scanner(span_exporter: InMemorySpanExporter) -> None:
    # span_exporter fixture sets a global SDK provider; install() attaches to it.
    from tracewarden.detectors import base

    saved = dict(base._REGISTRY)
    base._REGISTRY.clear()
    register("secrets")(lambda cfg: KeywordDetector())
    try:
        handle = tracewarden.install()
        assert handle.pipeline is not None
        assert handle.created_provider is False
        with tracewarden.llm_call(prompt="a bomb prompt"):
            pass
        (span_data,) = span_exporter.get_finished_spans()
        assert span_data.attributes is not None
        assert span_data.attributes.get(SPAN_EVENT_COUNT) == 1
    finally:
        tracewarden.uninstall()
        base._REGISTRY.clear()
        base._REGISTRY.update(saved)
