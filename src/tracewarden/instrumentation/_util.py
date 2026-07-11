"""Shared helpers for adapters."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Span

from tracewarden._hooks import scan
from tracewarden.schema import Surface

_TRACER_NAME = "tracewarden"

# Message roles → the surface their content is scanned as.
ROLE_SURFACE = {
    "system": Surface.SYSTEM_PROMPT,
    "developer": Surface.SYSTEM_PROMPT,
    "user": Surface.USER_PROMPT,
    "tool": Surface.TOOL_OUTPUT,  # tool results flowing back into the prompt
    "function": Surface.TOOL_OUTPUT,
}


@contextmanager
def carrier_span(name: str) -> Iterator[Span]:
    """Attach findings to the current recording span, or open a short-lived one
    when the adapter fires outside any trace (callback-style frameworks)."""
    current = trace.get_current_span()
    if current.get_span_context().is_valid and current.is_recording():
        yield current
    else:
        with trace.get_tracer(_TRACER_NAME).start_as_current_span(name) as span:
            yield span


def content_to_text(content: Any) -> str:
    """Flatten a message ``content`` field (str or list of typed parts) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                text = part.get("text") or part.get("content")
                if isinstance(text, str):
                    parts.append(text)
            else:
                text_attr = getattr(part, "text", None)
                if isinstance(text_attr, str):
                    parts.append(text_attr)
        return "\n".join(parts)
    return "" if content is None else str(content)


def scan_message(span: Span, role: str, content: Any) -> None:
    surface = ROLE_SURFACE.get(role)
    if surface is not None:
        scan(span, surface, content_to_text(content))


def dump_json(value: Any) -> str:
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return repr(value)
