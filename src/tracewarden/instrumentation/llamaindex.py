"""LlamaIndex adapter: an instrumentation-dispatcher event handler scanning
LLM prompts/completions and chat messages."""

from __future__ import annotations

from typing import Any

from tracewarden._hooks import scan
from tracewarden.instrumentation._util import carrier_span, content_to_text
from tracewarden.schema import Surface

_registered_handler: Any | None = None

_ROLE_SURFACE = {
    "system": Surface.SYSTEM_PROMPT,
    "user": Surface.USER_PROMPT,
    "tool": Surface.TOOL_OUTPUT,
}


def _make_handler_class() -> type[Any]:
    from llama_index.core.instrumentation.event_handlers import BaseEventHandler

    class TracewardenEventHandler(BaseEventHandler):
        @classmethod
        def class_name(cls) -> str:
            return "TracewardenEventHandler"

        def handle(self, event: Any, **kwargs: Any) -> None:
            name = type(event).__name__
            if name == "LLMCompletionStartEvent":
                with carrier_span("llm llamaindex") as span:
                    scan(span, Surface.USER_PROMPT, getattr(event, "prompt", "") or "")
            elif name == "LLMCompletionEndEvent":
                with carrier_span("llm llamaindex") as span:
                    scan(span, Surface.COMPLETION, str(getattr(event, "response", "") or ""))
            elif name == "LLMChatStartEvent":
                with carrier_span("chat llamaindex") as span:
                    for message in getattr(event, "messages", None) or ():
                        role = str(getattr(message, "role", ""))
                        surface = _ROLE_SURFACE.get(role.split(".")[-1].lower())
                        if surface:
                            scan(span, surface, content_to_text(getattr(message, "content", None)))
            elif name == "LLMChatEndEvent":
                with carrier_span("chat llamaindex") as span:
                    response = getattr(event, "response", None)
                    message = getattr(response, "message", None)
                    if message is not None:
                        scan(
                            span,
                            Surface.COMPLETION,
                            content_to_text(getattr(message, "content", None)),
                        )

    return TracewardenEventHandler


def instrument_llamaindex() -> None:
    global _registered_handler
    if _registered_handler is not None:
        return
    try:
        # llama-index re-exports without __all__, hence the attr-defined ignore
        from llama_index.core.instrumentation import get_dispatcher  # type: ignore[attr-defined]
    except ImportError as exc:
        from tracewarden.instrumentation import MissingDependencyError

        raise MissingDependencyError("llamaindex", "llamaindex") from exc

    handler = _make_handler_class()()
    get_dispatcher().add_event_handler(handler)
    _registered_handler = handler


def uninstrument_llamaindex() -> None:
    global _registered_handler
    if _registered_handler is None:
        return
    from llama_index.core.instrumentation import get_dispatcher  # type: ignore[attr-defined]

    dispatcher = get_dispatcher()
    dispatcher.event_handlers = [
        h for h in dispatcher.event_handlers if h is not _registered_handler
    ]
    _registered_handler = None
