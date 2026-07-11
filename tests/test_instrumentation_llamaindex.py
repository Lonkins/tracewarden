from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.conftest import RecordingScanner
from tracewarden.instrumentation.llamaindex import instrument_llamaindex, uninstrument_llamaindex
from tracewarden.schema import Surface


def _fire_chat_events() -> None:
    from llama_index.core.base.llms.types import (
        ChatMessage,
        ChatResponse,
        CompletionResponse,
        MessageRole,
    )
    from llama_index.core.instrumentation import get_dispatcher
    from llama_index.core.instrumentation.events.llm import (
        LLMChatEndEvent,
        LLMChatStartEvent,
        LLMCompletionEndEvent,
    )

    dispatcher = get_dispatcher()
    messages = [
        ChatMessage(role=MessageRole.SYSTEM, content="sys rules"),
        ChatMessage(role=MessageRole.USER, content="user asks"),
    ]
    dispatcher.event(LLMChatStartEvent(messages=messages, additional_kwargs={}, model_dict={}))
    dispatcher.event(
        LLMChatEndEvent(
            messages=messages,
            response=ChatResponse(
                message=ChatMessage(role=MessageRole.ASSISTANT, content="li reply")
            ),
        )
    )
    dispatcher.event(
        LLMCompletionEndEvent(prompt="raw prompt", response=CompletionResponse(text="raw out"))
    )


def test_llamaindex_events_scanned(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    instrument_llamaindex()
    try:
        _fire_chat_events()
    finally:
        uninstrument_llamaindex()

    assert recording_scanner.texts(Surface.SYSTEM_PROMPT) == ["sys rules"]
    assert recording_scanner.texts(Surface.USER_PROMPT) == ["user asks"]
    assert recording_scanner.texts(Surface.COMPLETION) == ["li reply", "raw out"]
    # events fired outside any span get short-lived carrier spans
    assert span_exporter.get_finished_spans()


def test_uninstrument_stops_scanning(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    instrument_llamaindex()
    uninstrument_llamaindex()
    _fire_chat_events()
    assert recording_scanner.seen == []
