"""LangChain adapter: a ``BaseCallbackHandler`` that opens a span per LLM/tool
run and scans prompts, generations, and tool input/output.

Attach it per-invoke (``config={"callbacks": [handler]}``) or globally via
``instrument_langchain()``, which registers it as a LangChain global handler.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from opentelemetry import trace
from opentelemetry.trace import Span

from tracewarden._hooks import scan
from tracewarden.schema import Surface

_registered_handler: Any | None = None


def _make_handler_class() -> type[Any]:
    from langchain_core.callbacks import BaseCallbackHandler

    class TracewardenCallbackHandler(BaseCallbackHandler):
        """Scans LangChain LLM and tool runs; one OTel span per run."""

        raise_error = False

        def __init__(self) -> None:
            self._spans: dict[UUID, Span] = {}
            self._tracer = trace.get_tracer("tracewarden")

        def _start(self, run_id: UUID, name: str) -> Span:
            span = self._tracer.start_span(name)
            self._spans[run_id] = span
            return span

        def _finish(self, run_id: UUID) -> None:
            span = self._spans.pop(run_id, None)
            if span is not None:
                span.end()

        # --- LLM runs -------------------------------------------------
        def on_llm_start(
            self, serialized: dict[str, Any], prompts: list[str], *, run_id: UUID, **kwargs: Any
        ) -> None:
            span = self._start(run_id, "llm langchain")
            for prompt in prompts:
                scan(span, Surface.USER_PROMPT, prompt)

        def on_chat_model_start(
            self,
            serialized: dict[str, Any],
            messages: list[list[Any]],
            *,
            run_id: UUID,
            **kwargs: Any,
        ) -> None:
            span = self._start(run_id, "chat langchain")
            surface_by_type = {
                "system": Surface.SYSTEM_PROMPT,
                "human": Surface.USER_PROMPT,
                "tool": Surface.TOOL_OUTPUT,
            }
            for batch in messages:
                for message in batch:
                    surface = surface_by_type.get(getattr(message, "type", ""))
                    text = getattr(message, "text", None) or getattr(message, "content", "")
                    if surface and isinstance(text, str):
                        scan(span, surface, text)

        def on_llm_end(self, response: Any, *, run_id: UUID, **kwargs: Any) -> None:
            span = self._spans.get(run_id)
            if span is not None:
                for batch in getattr(response, "generations", None) or ():
                    for generation in batch:
                        text = getattr(generation, "text", "")
                        if text:
                            scan(span, Surface.COMPLETION, text)
            self._finish(run_id)

        def on_llm_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
            self._finish(run_id)

        # --- Tool runs ------------------------------------------------
        def on_tool_start(
            self, serialized: dict[str, Any], input_str: str, *, run_id: UUID, **kwargs: Any
        ) -> None:
            name = serialized.get("name", "tool")
            span = self._start(run_id, f"tool {name}")
            span.set_attribute("tool.name", name)
            scan(span, Surface.TOOL_INPUT, input_str, {"tool_name": name})

        def on_tool_end(self, output: Any, *, run_id: UUID, **kwargs: Any) -> None:
            span = self._spans.get(run_id)
            if span is not None:
                scan(span, Surface.TOOL_OUTPUT, str(output))
            self._finish(run_id)

        def on_tool_error(self, error: BaseException, *, run_id: UUID, **kwargs: Any) -> None:
            self._finish(run_id)

    return TracewardenCallbackHandler


def get_callback_handler() -> Any:
    """A fresh handler to pass in ``callbacks=[...]``."""
    try:
        return _make_handler_class()()
    except ImportError as exc:
        from tracewarden.instrumentation import MissingDependencyError

        raise MissingDependencyError("langchain", "langchain") from exc


def instrument_langchain() -> None:
    """Register the handler globally so every LangChain run is scanned."""
    global _registered_handler
    if _registered_handler is not None:
        return
    try:
        from langchain_core.tracers.context import register_configure_hook
    except ImportError as exc:
        from tracewarden.instrumentation import MissingDependencyError

        raise MissingDependencyError("langchain", "langchain") from exc

    import contextvars

    handler = get_callback_handler()
    var: contextvars.ContextVar[Any] = contextvars.ContextVar(
        "tracewarden_callback", default=handler
    )
    register_configure_hook(var, inheritable=True)
    _registered_handler = handler


def uninstrument_langchain() -> None:
    """LangChain has no unregister API for configure hooks; neutralize ours."""
    global _registered_handler
    if _registered_handler is None:
        return
    from langchain_core.tracers.context import _configure_hooks

    for i, (var, *_rest) in enumerate(list(_configure_hooks)):
        if var.name == "tracewarden_callback":
            del _configure_hooks[i]
            break
    _registered_handler = None
