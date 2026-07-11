"""PydanticAI adapter: wraps ``Agent.run`` (which ``run_sync`` also routes
through) to scan the user prompt and the final output.

Tool-level coverage inside PydanticAI graphs is not patched — use
``tracewarden.manual.guarded_tool`` on tool functions, or the MCP adapter when
tools are MCP-backed.
"""

from __future__ import annotations

from typing import Any

from opentelemetry import trace

from tracewarden._hooks import scan
from tracewarden.instrumentation._util import content_to_text
from tracewarden.schema import Surface

_ORIGINALS: dict[str, Any] = {}


def instrument_pydantic_ai() -> None:
    try:
        from pydantic_ai import Agent
    except ImportError as exc:
        from tracewarden.instrumentation import MissingDependencyError

        raise MissingDependencyError("pydantic_ai", "pydantic-ai") from exc

    if _ORIGINALS:
        return
    tracer = trace.get_tracer("tracewarden")
    run_orig = Agent.run

    async def run_wrapper(self: Any, user_prompt: Any = None, /, *args: Any, **kwargs: Any) -> Any:
        with tracer.start_as_current_span("agent pydantic_ai") as span:
            span.set_attribute("gen_ai.system", "pydantic_ai")
            scan(span, Surface.USER_PROMPT, content_to_text(user_prompt))
            result = await run_orig(self, user_prompt, *args, **kwargs)
            output = getattr(result, "output", None)
            if output is None:  # pydantic-ai < 0.1 used .data
                output = getattr(result, "data", None)
            if output is not None:
                scan(span, Surface.COMPLETION, str(output))
            return result

    _ORIGINALS["run"] = run_orig
    Agent.run = run_wrapper  # type: ignore[assignment,method-assign]


def uninstrument_pydantic_ai() -> None:
    if not _ORIGINALS:
        return
    from pydantic_ai import Agent

    Agent.run = _ORIGINALS.pop("run")  # type: ignore[method-assign]
