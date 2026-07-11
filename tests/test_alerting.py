import json
from pathlib import Path

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import Span

from tracewarden.alerting import (
    Alert,
    AlertManager,
    AlertRule,
    file_sink,
    stream_sink,
    webhook_sink,
)
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface


def make_event(
    type_: EventType = EventType.SECRET_LEAK, severity: Severity = Severity.HIGH
) -> SecurityEvent:
    return SecurityEvent(
        type=type_,
        severity=severity,
        detector="tracewarden.secrets",
        rule="aws_access_key_id",
        surface=Surface.TOOL_OUTPUT,
        evidence="AK…LE (len=20)",
    )


def span() -> Span:
    return TracerProvider().get_tracer("t").start_span("s")


def test_rule_matches_by_severity() -> None:
    rule = AlertRule(min_severity=Severity.HIGH)
    assert rule.matches(make_event(severity=Severity.HIGH))
    assert rule.matches(make_event(severity=Severity.CRITICAL))
    assert not rule.matches(make_event(severity=Severity.MEDIUM))


def test_rule_matches_by_type() -> None:
    rule = AlertRule(min_severity=Severity.LOW, types=frozenset({EventType.SECRET_LEAK}))
    assert rule.matches(make_event(EventType.SECRET_LEAK, Severity.LOW))
    assert not rule.matches(make_event(EventType.PII_LEAK, Severity.CRITICAL))


def test_manager_fires_once_per_event_to_all_sinks() -> None:
    seen_a: list[Alert] = []
    seen_b: list[Alert] = []
    manager = AlertManager(
        rules=(AlertRule(min_severity=Severity.HIGH),),
        sinks=(seen_a.append, seen_b.append),
    )
    manager(span(), [make_event(severity=Severity.HIGH), make_event(severity=Severity.LOW)])
    assert len(seen_a) == 1  # low-severity filtered out
    assert len(seen_b) == 1
    assert seen_a[0].event.severity is Severity.HIGH


def test_manager_dedupes_across_multiple_matching_rules() -> None:
    seen: list[Alert] = []
    manager = AlertManager(
        rules=(
            AlertRule(min_severity=Severity.HIGH, name="a"),
            AlertRule(min_severity=Severity.LOW, name="b"),
        ),
        sinks=(seen.append,),
    )
    manager(span(), [make_event(severity=Severity.HIGH)])
    assert len(seen) == 1  # matched two rules but dispatched once


def test_stream_sink_writes_line() -> None:
    import io

    buffer = io.StringIO()
    AlertManager(sinks=(stream_sink(buffer),))(span(), [make_event()])
    output = buffer.getvalue()
    assert "HIGH" in output
    assert "secret_leak" in output


def test_file_sink_writes_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "alerts.jsonl"
    AlertManager(sinks=(file_sink(out),))(span(), [make_event(), make_event()])
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert record["type"] == "secret_leak"
    assert record["severity"] == "high"
    assert "trace_id" in record


def test_webhook_sink_posts_json(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import urllib.request

    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(request: urllib.request.Request, timeout: float = 0) -> FakeResponse:
        captured["url"] = request.full_url
        captured["method"] = request.method
        captured["body"] = json.loads(request.data or b"{}")
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    AlertManager(sinks=(webhook_sink("http://localhost:9999/hook"),))(span(), [make_event()])
    assert captured["url"] == "http://localhost:9999/hook"
    assert captured["method"] == "POST"
    assert captured["body"]["type"] == "secret_leak"  # type: ignore[index]


def test_webhook_failure_is_non_fatal(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import urllib.error
    import urllib.request

    def boom(request: object, timeout: float = 0) -> None:
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    # must not raise
    AlertManager(sinks=(webhook_sink("http://localhost:9999/hook"),))(span(), [make_event()])


def test_bad_sink_does_not_block_other_sinks() -> None:
    good: list[Alert] = []

    def bad(alert: Alert) -> None:
        raise RuntimeError("sink exploded")

    AlertManager(sinks=(bad, good.append))(span(), [make_event()])
    assert len(good) == 1
