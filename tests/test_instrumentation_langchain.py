from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.conftest import RecordingScanner
from tracewarden.instrumentation.langchain import (
    get_callback_handler,
    instrument_langchain,
    uninstrument_langchain,
)
from tracewarden.schema import Surface


def test_chat_model_run_scanned(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    from langchain_core.messages import HumanMessage, SystemMessage

    handler = get_callback_handler()
    model = FakeListChatModel(responses=["faked reply"])
    model.invoke(
        [SystemMessage(content="rules"), HumanMessage(content="question")],
        config={"callbacks": [handler]},
    )

    assert recording_scanner.texts(Surface.SYSTEM_PROMPT) == ["rules"]
    assert recording_scanner.texts(Surface.USER_PROMPT) == ["question"]
    assert recording_scanner.texts(Surface.COMPLETION) == ["faked reply"]
    spans = span_exporter.get_finished_spans()
    assert [s.name for s in spans] == ["chat langchain"]


def test_llm_run_scanned(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    from langchain_core.language_models.fake import FakeListLLM

    handler = get_callback_handler()
    llm = FakeListLLM(responses=["plain response"])
    llm.invoke("plain prompt", config={"callbacks": [handler]})

    assert recording_scanner.texts(Surface.USER_PROMPT) == ["plain prompt"]
    assert recording_scanner.texts(Surface.COMPLETION) == ["plain response"]


def test_tool_run_scanned(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    from langchain_core.tools import tool

    @tool
    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo: {text}"

    handler = get_callback_handler()
    echo.invoke({"text": "ping"}, config={"callbacks": [handler]})

    assert any("ping" in t for t in recording_scanner.texts(Surface.TOOL_INPUT))
    assert any("echo: ping" in t for t in recording_scanner.texts(Surface.TOOL_OUTPUT))
    assert any(s.name == "tool echo" for s in span_exporter.get_finished_spans())


def test_global_instrumentation_registers_and_unregisters(
    span_exporter: InMemorySpanExporter, recording_scanner: RecordingScanner
) -> None:
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    from langchain_core.messages import HumanMessage

    instrument_langchain()
    try:
        FakeListChatModel(responses=["auto"]).invoke([HumanMessage(content="global hook")])
        assert recording_scanner.texts(Surface.USER_PROMPT) == ["global hook"]
    finally:
        uninstrument_langchain()

    before = len(recording_scanner.seen)
    FakeListChatModel(responses=["auto2"]).invoke([HumanMessage(content="after remove")])
    assert len(recording_scanner.seen) == before
