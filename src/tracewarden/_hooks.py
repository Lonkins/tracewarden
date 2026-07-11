"""The seam between instrumentation and detection.

Adapters call :func:`scan` with every piece of content they see (prompts, tool
inputs/outputs, memory writes). Whatever is registered via
:func:`register_scanner` — normally the detection pipeline — runs over it.
Content is scanned, never stored: tracewarden does not copy prompts onto spans.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping

from opentelemetry.trace import Span

from tracewarden.schema import Surface

type MetaValue = str | int | float | bool
type Scanner = Callable[[Span, Surface, str, Mapping[str, MetaValue]], None]

_scanners: list[Scanner] = []
_logger = logging.getLogger("tracewarden")
_warned_scanners: set[str] = set()


def register_scanner(scanner: Scanner) -> None:
    if scanner not in _scanners:
        _scanners.append(scanner)


def clear_scanners() -> None:
    _scanners.clear()


def scan(
    span: Span,
    surface: Surface,
    text: str | None,
    meta: Mapping[str, MetaValue] | None = None,
) -> None:
    """Run all registered scanners over one piece of content. Detection failures
    never break the instrumented call."""
    if not text:
        return
    for scanner in list(_scanners):
        try:
            scanner(span, surface, text, meta or {})
        except Exception:
            key = repr(scanner)
            if key not in _warned_scanners:
                _warned_scanners.add(key)
                _logger.warning("tracewarden scanner %s failed; suppressing", key, exc_info=True)
