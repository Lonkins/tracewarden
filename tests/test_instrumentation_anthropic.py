from collections.abc import Iterator

import httpx
import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.conftest import RecordingScanner
from tracewarden.instrumentation.anthropic_sdk import instrument_anthropic, uninstrument_anthropic
from tracewarden.schema import Surface

MESSAGE_BODY = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5",
    "content": [
        {"type": "text", "text": "done"},
        {"type": "tool_use", "id": "tu_1", "name": "fetch", "input": {"url": "http://x"}},
    ],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 1, "output_tokens": 1},
}


@pytest.fixture()
def instrumented() -> Iterator[None]:
    instrument_anthropic()
    yield
    uninstrument_anthropic()


def test_messages_create_scanned(
    span_exporter: InMemorySpanExporter,
    recording_scanner: RecordingScanner,
    instrumented: None,
) -> None:
    import anthropic

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=MESSAGE_BODY)

    client = anthropic.Anthropic(
        api_key="test-key-not-real",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client.messages.create(
        model="claude-sonnet-5",
        max_tokens=64,
        system="stay safe",
        messages=[
            {"role": "user", "content": "hi"},
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "tu_0", "content": "tool says hi"}
                ],
            },
        ],
    )

    assert recording_scanner.texts(Surface.SYSTEM_PROMPT) == ["stay safe"]
    assert recording_scanner.texts(Surface.USER_PROMPT) == ["hi", "tool says hi"]
    assert recording_scanner.texts(Surface.TOOL_OUTPUT) == ["tool says hi"]
    assert recording_scanner.texts(Surface.COMPLETION) == ["done"]
    tool_inputs = recording_scanner.seen
    assert any(
        s is Surface.TOOL_INPUT and meta.get("tool_name") == "fetch" for s, _, meta in tool_inputs
    )
    (span,) = span_exporter.get_finished_spans()
    assert span.name == "chat anthropic"


def test_uninstrument_restores_original() -> None:
    from anthropic.resources import messages

    original = messages.Messages.create
    instrument_anthropic()
    assert messages.Messages.create is not original
    uninstrument_anthropic()
    assert messages.Messages.create is original
