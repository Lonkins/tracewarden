"""Explicit instrumentation: context managers and a decorator for code the
auto-adapters don't cover."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Span

from tracewarden._hooks import scan
from tracewarden.schema import Surface

_TRACER_NAME = "tracewarden"


def _tracer() -> trace.Tracer:
    return trace.get_tracer(_TRACER_NAME)


@dataclass
class SpanScanner:
    """Handed to the caller inside the context managers: feed it the content
    you want scanned as it becomes available."""

    span: Span

    def record(self, surface: Surface, text: str | None, **meta: str | int | float | bool) -> None:
        scan(self.span, surface, text, meta)


@contextmanager
def llm_call(
    name: str = "llm.call",
    *,
    system: str | None = None,
    prompt: str | None = None,
) -> Iterator[SpanScanner]:
    """Span for one model call. Scan the completion via ``.record(Surface.COMPLETION, ...)``."""
    with _tracer().start_as_current_span(name) as span:
        scanner = SpanScanner(span)
        scanner.record(Surface.SYSTEM_PROMPT, system)
        scanner.record(Surface.USER_PROMPT, prompt)
        yield scanner


@contextmanager
def tool_call(tool_name: str, *, arguments: str | None = None) -> Iterator[SpanScanner]:
    """Span for one tool invocation."""
    with _tracer().start_as_current_span(f"tool {tool_name}") as span:
        span.set_attribute("tool.name", tool_name)
        scanner = SpanScanner(span)
        scanner.record(Surface.TOOL_INPUT, arguments, tool_name=tool_name)
        yield scanner


@contextmanager
def memory_write(store: str = "memory") -> Iterator[SpanScanner]:
    """Span for a write into agent memory / a vector store."""
    with _tracer().start_as_current_span(f"memory.write {store}") as span:
        span.set_attribute("memory.store", store)
        yield SpanScanner(span)


def stringify_arguments(*args: Any, **kwargs: Any) -> str:
    """Best-effort JSON rendering of call arguments for scanning."""
    try:
        return json.dumps({"args": args, "kwargs": kwargs}, default=str)
    except (TypeError, ValueError):
        return repr((args, kwargs))


def guarded_tool[**P, R](func: Callable[P, R]) -> Callable[P, R]:
    """Decorator: wrap a tool function so its inputs and output are scanned."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        name = func.__name__
        with tool_call(name, arguments=stringify_arguments(*args, **kwargs)) as scanner:
            result = func(*args, **kwargs)
            scanner.record(Surface.TOOL_OUTPUT, str(result), tool_name=name)
            return result

    return wrapper
