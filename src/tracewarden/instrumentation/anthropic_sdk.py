"""Anthropic SDK adapter: wraps ``messages.create`` (sync + async).

Scans the system prompt, outgoing messages (including tool_result blocks), and
on non-streaming responses the completion text and tool_use arguments.
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace

from tracewarden._hooks import scan
from tracewarden.instrumentation._util import content_to_text, dump_json, scan_message
from tracewarden.schema import Surface

_ORIGINALS: dict[str, Any] = {}


def _block_role(block: Any) -> str | None:
    block_type = block.get("type") if isinstance(block, dict) else getattr(block, "type", None)
    return "tool" if block_type == "tool_result" else None


def _scan_request(span: trace.Span, kwargs: dict[str, Any]) -> None:
    system = kwargs.get("system")
    if system:
        scan(span, Surface.SYSTEM_PROMPT, content_to_text(system))
    for message in kwargs.get("messages") or ():
        role = (
            message.get("role", "") if isinstance(message, dict) else getattr(message, "role", "")
        )
        content = (
            message.get("content")
            if isinstance(message, dict)
            else getattr(message, "content", None)
        )
        # tool_result blocks are tool output re-entering the prompt; scan separately
        if isinstance(content, list):
            for block in content:
                if _block_role(block) == "tool":
                    scan(
                        span,
                        Surface.TOOL_OUTPUT,
                        content_to_text(
                            block.get("content")
                            if isinstance(block, dict)
                            else getattr(block, "content", None)
                        ),
                    )
        scan_message(span, role, content)


def _scan_response(span: trace.Span, response: Any) -> None:
    for block in getattr(response, "content", None) or ():
        block_type = getattr(block, "type", None)
        if block_type == "text":
            scan(span, Surface.COMPLETION, getattr(block, "text", "") or "")
        elif block_type == "tool_use":
            scan(
                span,
                Surface.TOOL_INPUT,
                dump_json(getattr(block, "input", None)),
                {"tool_name": getattr(block, "name", "") or ""},
            )


def instrument_anthropic() -> None:
    try:
        from anthropic.resources import messages
    except ImportError as exc:
        from tracewarden.instrumentation import MissingDependencyError

        raise MissingDependencyError("anthropic", "anthropic") from exc

    if _ORIGINALS:
        return
    tracer = trace.get_tracer("tracewarden")
    sync_orig = messages.Messages.create
    async_orig = messages.AsyncMessages.create

    def sync_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        with tracer.start_as_current_span("chat anthropic") as span:
            span.set_attribute("gen_ai.system", "anthropic")
            _scan_request(span, kwargs)
            response = sync_orig(self, *args, **kwargs)
            if not kwargs.get("stream"):
                _scan_response(span, response)
            return response

    async def async_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        with tracer.start_as_current_span("chat anthropic") as span:
            span.set_attribute("gen_ai.system", "anthropic")
            _scan_request(span, kwargs)
            response = await async_orig(self, *args, **kwargs)
            if not kwargs.get("stream"):
                _scan_response(span, response)
            return response

    _ORIGINALS["sync"] = sync_orig
    _ORIGINALS["async"] = async_orig
    messages.Messages.create = sync_wrapper  # type: ignore[method-assign]
    messages.AsyncMessages.create = async_wrapper  # type: ignore[method-assign]


def uninstrument_anthropic() -> None:
    if not _ORIGINALS:
        return
    from anthropic.resources import messages

    messages.Messages.create = _ORIGINALS.pop("sync")  # type: ignore[method-assign]
    messages.AsyncMessages.create = _ORIGINALS.pop("async")  # type: ignore[method-assign]
