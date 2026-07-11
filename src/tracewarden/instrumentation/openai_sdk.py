"""OpenAI SDK adapter: wraps ``chat.completions.create`` (sync + async).

Scans outgoing messages by role and, on non-streaming responses, the returned
completion text and any tool-call arguments. Streaming responses pass through
unscanned on the output side (documented limitation).
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace

from tracewarden._hooks import scan
from tracewarden.instrumentation._util import scan_message
from tracewarden.schema import Surface

_ORIGINALS: dict[str, Any] = {}


def _scan_request(span: trace.Span, kwargs: dict[str, Any]) -> None:
    for message in kwargs.get("messages") or ():
        role = (
            message.get("role", "") if isinstance(message, dict) else getattr(message, "role", "")
        )
        content = (
            message.get("content")
            if isinstance(message, dict)
            else getattr(message, "content", None)
        )
        scan_message(span, role, content)


def _scan_response(span: trace.Span, response: Any) -> None:
    for choice in getattr(response, "choices", None) or ():
        message = getattr(choice, "message", None)
        if message is None:
            continue
        content = getattr(message, "content", None)
        if isinstance(content, str):
            scan(span, Surface.COMPLETION, content)
        for tool_call in getattr(message, "tool_calls", None) or ():
            function = getattr(tool_call, "function", None)
            if function is not None:
                scan(
                    span,
                    Surface.TOOL_INPUT,
                    getattr(function, "arguments", "") or "",
                    {"tool_name": getattr(function, "name", "") or ""},
                )


def instrument_openai() -> None:
    try:
        from openai.resources.chat import completions
    except ImportError as exc:
        from tracewarden.instrumentation import MissingDependencyError

        raise MissingDependencyError("openai", "openai") from exc

    if _ORIGINALS:
        return
    tracer = trace.get_tracer("tracewarden")
    sync_orig = completions.Completions.create
    async_orig = completions.AsyncCompletions.create

    def sync_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        with tracer.start_as_current_span("chat openai") as span:
            span.set_attribute("gen_ai.system", "openai")
            _scan_request(span, kwargs)
            response = sync_orig(self, *args, **kwargs)
            if not kwargs.get("stream"):
                _scan_response(span, response)
            return response

    async def async_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        with tracer.start_as_current_span("chat openai") as span:
            span.set_attribute("gen_ai.system", "openai")
            _scan_request(span, kwargs)
            response = await async_orig(self, *args, **kwargs)
            if not kwargs.get("stream"):
                _scan_response(span, response)
            return response

    _ORIGINALS["sync"] = sync_orig
    _ORIGINALS["async"] = async_orig
    completions.Completions.create = sync_wrapper  # type: ignore[method-assign]
    completions.AsyncCompletions.create = async_wrapper  # type: ignore[method-assign]


def uninstrument_openai() -> None:
    if not _ORIGINALS:
        return
    from openai.resources.chat import completions

    completions.Completions.create = _ORIGINALS.pop("sync")  # type: ignore[method-assign]
    completions.AsyncCompletions.create = _ORIGINALS.pop("async")  # type: ignore[method-assign]
