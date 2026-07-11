"""MCP client adapter: wraps ``ClientSession.call_tool`` and ``list_tools``.

- ``call_tool``: tool arguments scanned as tool_input, result content as
  tool_output — the classic indirect-injection path.
- ``list_tools``: tool *descriptions* scanned as tool_description — the
  tool-poisoning surface (malicious instructions hidden in tool metadata).
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace

from tracewarden._hooks import scan
from tracewarden.instrumentation._util import dump_json
from tracewarden.schema import Surface

_ORIGINALS: dict[str, Any] = {}


def _result_text(result: Any) -> str:
    parts: list[str] = []
    for block in getattr(result, "content", None) or ():
        text = getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def instrument_mcp() -> None:
    try:
        from mcp.client.session import ClientSession
    except ImportError as exc:
        from tracewarden.instrumentation import MissingDependencyError

        raise MissingDependencyError("mcp", "mcp") from exc

    if _ORIGINALS:
        return
    tracer = trace.get_tracer("tracewarden")
    call_tool_orig = ClientSession.call_tool
    list_tools_orig = ClientSession.list_tools

    async def call_tool_wrapper(
        self: Any, name: str, arguments: dict[str, Any] | None = None, *args: Any, **kwargs: Any
    ) -> Any:
        with tracer.start_as_current_span(f"tool {name}") as span:
            span.set_attribute("tool.name", name)
            span.set_attribute("mcp.method", "tools/call")
            if arguments:
                scan(span, Surface.TOOL_INPUT, dump_json(arguments), {"tool_name": name})
            result = await call_tool_orig(self, name, arguments, *args, **kwargs)
            text = _result_text(result)
            if text:
                scan(span, Surface.TOOL_OUTPUT, text, {"tool_name": name})
            return result

    async def list_tools_wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        with tracer.start_as_current_span("mcp tools/list") as span:
            span.set_attribute("mcp.method", "tools/list")
            result = await list_tools_orig(self, *args, **kwargs)
            for tool in getattr(result, "tools", None) or ():
                description = getattr(tool, "description", None)
                if description:
                    scan(
                        span,
                        Surface.TOOL_DESCRIPTION,
                        description,
                        {"tool_name": getattr(tool, "name", "") or ""},
                    )
            return result

    _ORIGINALS["call_tool"] = call_tool_orig
    _ORIGINALS["list_tools"] = list_tools_orig
    ClientSession.call_tool = call_tool_wrapper  # type: ignore[method-assign]
    ClientSession.list_tools = list_tools_wrapper  # type: ignore[method-assign]


def uninstrument_mcp() -> None:
    if not _ORIGINALS:
        return
    from mcp.client.session import ClientSession

    ClientSession.call_tool = _ORIGINALS.pop("call_tool")  # type: ignore[method-assign]
    ClientSession.list_tools = _ORIGINALS.pop("list_tools")  # type: ignore[method-assign]
