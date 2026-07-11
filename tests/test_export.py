import json
from pathlib import Path

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tracewarden.export import LANGFUSE_PREFIX, OPENINFERENCE_PREFIX, annotate_for_backends
from tracewarden.pipeline import DetectionPipeline
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface


class AlwaysFlags:
    id = "test.always"
    toggle = "secrets"

    def scan(self, ctx: object) -> list[SecurityEvent]:
        return [
            SecurityEvent(
                type=EventType.SECRET_LEAK,
                severity=Severity.CRITICAL,
                detector=self.id,
                rule="x",
                surface=Surface.COMPLETION,
            )
        ]


def make_provider() -> tuple[TracerProvider, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


def test_annotate_writes_both_backend_namespaces() -> None:
    provider, exporter = make_provider()
    with provider.get_tracer("t").start_as_current_span("s") as span:
        annotate_for_backends(span, event_count=2, max_severity="high", event_types=["secret_leak"])
    (span_data,) = exporter.get_finished_spans()
    attrs = span_data.attributes or {}
    for prefix in (LANGFUSE_PREFIX, OPENINFERENCE_PREFIX):
        assert attrs[f"{prefix}.event_count"] == 2
        assert attrs[f"{prefix}.max_severity"] == "high"
        assert tuple(attrs[f"{prefix}.event_types"]) == ("secret_leak",)  # type: ignore[arg-type]


def test_pipeline_annotates_by_default() -> None:
    provider, exporter = make_provider()
    pipeline = DetectionPipeline([AlwaysFlags()])  # type: ignore[list-item]
    with provider.get_tracer("t").start_as_current_span("s") as span:
        pipeline(span, Surface.COMPLETION, "text", {})
    (span_data,) = exporter.get_finished_spans()
    attrs = span_data.attributes or {}
    assert attrs[f"{LANGFUSE_PREFIX}.max_severity"] == "critical"


def test_pipeline_annotation_can_be_disabled() -> None:
    provider, exporter = make_provider()
    pipeline = DetectionPipeline([AlwaysFlags()], annotate_backends=False)  # type: ignore[list-item]
    with provider.get_tracer("t").start_as_current_span("s") as span:
        pipeline(span, Surface.COMPLETION, "text", {})
    (span_data,) = exporter.get_finished_spans()
    attrs = span_data.attributes or {}
    assert f"{LANGFUSE_PREFIX}.max_severity" not in attrs


def test_grafana_dashboard_is_valid_json_and_references_schema() -> None:
    path = Path(__file__).resolve().parents[1] / "dashboards" / "tracewarden-grafana.json"
    dashboard = json.loads(path.read_text())
    assert dashboard["title"]
    queries = [t["query"] for panel in dashboard["panels"] for t in panel.get("targets", [])]
    joined = " ".join(queries)
    assert "security.event.type" in joined
    assert "secret_leak" in joined
    assert "prompt_injection" in joined
