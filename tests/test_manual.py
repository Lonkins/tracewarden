from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.conftest import RecordingScanner
from tracewarden.manual import guarded_tool, llm_call, memory_write, tool_call
from tracewarden.schema import Surface


def test_llm_call_scans_prompts_and_completion(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    with llm_call(system="be terse", prompt="hello") as scanner:
        scanner.record(Surface.COMPLETION, "hi there")

    assert recording_scanner.texts(Surface.SYSTEM_PROMPT) == ["be terse"]
    assert recording_scanner.texts(Surface.USER_PROMPT) == ["hello"]
    assert recording_scanner.texts(Surface.COMPLETION) == ["hi there"]
    (span,) = span_exporter.get_finished_spans()
    assert span.name == "llm.call"


def test_tool_call_span_and_meta(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    with tool_call("search", arguments='{"q": "x"}'):
        pass
    surface, _text, meta = recording_scanner.seen[0]
    assert surface is Surface.TOOL_INPUT
    assert meta["tool_name"] == "search"
    (span,) = span_exporter.get_finished_spans()
    assert span.name == "tool search"
    assert span.attributes is not None
    assert span.attributes["tool.name"] == "search"


def test_memory_write_span(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    with memory_write("mem0") as scanner:
        scanner.record(Surface.MEMORY_WRITE, "user prefers tabs")
    assert recording_scanner.texts(Surface.MEMORY_WRITE) == ["user prefers tabs"]
    (span,) = span_exporter.get_finished_spans()
    assert span.name == "memory.write mem0"


def test_guarded_tool_scans_in_and_out(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    @guarded_tool
    def lookup(city: str) -> str:
        return f"weather in {city}: sunny"

    assert lookup("Oslo") == "weather in Oslo: sunny"
    assert "Oslo" in recording_scanner.texts(Surface.TOOL_INPUT)[0]
    assert recording_scanner.texts(Surface.TOOL_OUTPUT) == ["weather in Oslo: sunny"]


def test_scanner_errors_do_not_break_the_call(
    span_exporter: InMemorySpanExporter,
) -> None:
    from tracewarden import _hooks

    def broken(*args: object) -> None:
        raise RuntimeError("detector exploded")

    _hooks.register_scanner(broken)  # type: ignore[arg-type]
    try:
        with llm_call(prompt="still works"):
            pass
    finally:
        _hooks.clear_scanners()
