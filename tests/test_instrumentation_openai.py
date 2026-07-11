import json
from collections.abc import Iterator

import httpx
import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.conftest import RecordingScanner
from tracewarden.instrumentation.openai_sdk import instrument_openai, uninstrument_openai
from tracewarden.schema import Surface

COMPLETION_BODY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 1,
    "model": "gpt-4o-mini",
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": "the answer",
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "search", "arguments": '{"q": "leak"}'},
                    }
                ],
            },
        }
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}


@pytest.fixture()
def instrumented() -> Iterator[None]:
    instrument_openai()
    yield
    uninstrument_openai()


def make_client() -> "object":
    import openai

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=COMPLETION_BODY)

    return openai.OpenAI(
        api_key="test-key-not-real",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def test_chat_completion_scanned(
    span_exporter: InMemorySpanExporter,
    recording_scanner: RecordingScanner,
    instrumented: None,
) -> None:
    client = make_client()
    response = client.chat.completions.create(  # type: ignore[attr-defined]
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "you are terse"},
            {"role": "user", "content": "what is the answer?"},
        ],
    )
    assert response.choices[0].message.content == "the answer"

    assert recording_scanner.texts(Surface.SYSTEM_PROMPT) == ["you are terse"]
    assert recording_scanner.texts(Surface.USER_PROMPT) == ["what is the answer?"]
    assert recording_scanner.texts(Surface.COMPLETION) == ["the answer"]
    # tool-call arguments requested by the model are scanned as tool input
    tool_inputs = recording_scanner.texts(Surface.TOOL_INPUT)
    assert json.loads(tool_inputs[0]) == {"q": "leak"}

    spans = span_exporter.get_finished_spans()
    assert [s.name for s in spans] == ["chat openai"]
    assert spans[0].attributes is not None
    assert spans[0].attributes["gen_ai.system"] == "openai"


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_async_chat_completion_scanned(
    span_exporter: InMemorySpanExporter,
    recording_scanner: RecordingScanner,
    instrumented: None,
) -> None:
    import openai

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=COMPLETION_BODY)

    client = openai.AsyncOpenAI(
        api_key="test-key-not-real",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": "async question"}],
    )
    assert recording_scanner.texts(Surface.USER_PROMPT) == ["async question"]
    assert recording_scanner.texts(Surface.COMPLETION) == ["the answer"]


def test_uninstrument_restores_original() -> None:
    from openai.resources.chat import completions

    original = completions.Completions.create
    instrument_openai()
    assert completions.Completions.create is not original
    uninstrument_openai()
    assert completions.Completions.create is original
