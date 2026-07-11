"""Alerting layer: fire on security-event classes to stdout / file / webhook.

A rule matches findings by event type and minimum severity; matched findings
are formatted and dispatched to one or more sinks. Wire it in via
``install(on_events=AlertManager(...))`` — an AlertManager is callable with the
pipeline's ``on_events`` signature.

Sinks are deterministic and local by default. The webhook sink posts JSON with
the stdlib; no external client, no paid service.
"""

from __future__ import annotations

import json
import logging
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from opentelemetry.trace import Span

from tracewarden.schema import EventType, SecurityEvent, Severity

_logger = logging.getLogger("tracewarden")

Sink = Callable[["Alert"], None]


@dataclass(frozen=True)
class Alert:
    """A matched finding plus its trace/span context, ready to dispatch."""

    event: SecurityEvent
    trace_id: str
    span_id: str

    def to_dict(self) -> dict[str, object]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "type": self.event.type.value,
            "severity": self.event.severity.value,
            "confidence": self.event.confidence,
            "detector": self.event.detector,
            "rule": self.event.rule,
            "surface": self.event.surface.value,
            "evidence": self.event.evidence,
        }

    def format_line(self) -> str:
        e = self.event
        return (
            f"[tracewarden] {e.severity.value.upper()} {e.type.value} "
            f"detector={e.detector} rule={e.rule} surface={e.surface.value} "
            f"trace={self.trace_id} evidence={e.evidence!r}"
        )


@dataclass(frozen=True)
class AlertRule:
    """Fire when a finding's type is in ``types`` (or any) and severity ≥ ``min_severity``."""

    min_severity: Severity = Severity.HIGH
    types: frozenset[EventType] | None = None
    name: str = "default"

    def matches(self, event: SecurityEvent) -> bool:
        if event.severity.rank < self.min_severity.rank:
            return False
        return self.types is None or event.type in self.types


# --- sinks -----------------------------------------------------------------


def stdout_sink(alert: Alert) -> None:
    print(alert.format_line(), file=sys.stderr)


def stream_sink(stream: TextIO) -> Sink:
    def sink(alert: Alert) -> None:
        stream.write(alert.format_line() + "\n")
        stream.flush()

    return sink


def file_sink(path: str | Path) -> Sink:
    """Append one JSON line per alert to ``path`` (JSONL)."""
    target = Path(path)

    def sink(alert: Alert) -> None:
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict()) + "\n")

    return sink


def webhook_sink(url: str, *, timeout: float = 5.0) -> Sink:
    """POST the alert as JSON to ``url``. Failures are logged, never raised."""

    def sink(alert: Alert) -> None:
        payload = json.dumps(alert.to_dict()).encode()
        request = urllib.request.Request(  # noqa: S310 — caller-provided webhook URL by design
            url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout):  # noqa: S310
                pass
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            _logger.warning("tracewarden webhook alert failed: %s", exc)

    return sink


# --- manager ---------------------------------------------------------------


@dataclass
class AlertManager:
    """Callable matching the pipeline ``on_events`` signature.

    Each finding is checked against every rule; on the first matching rule it is
    dispatched to all sinks (once per finding, not once per rule).
    """

    rules: Sequence[AlertRule] = field(default_factory=lambda: (AlertRule(),))
    sinks: Sequence[Sink] = field(default_factory=lambda: (stdout_sink,))

    def __call__(self, span: Span, events: Iterable[SecurityEvent]) -> None:
        ctx = span.get_span_context()
        trace_id = format(ctx.trace_id, "032x")
        span_id = format(ctx.span_id, "016x")
        for event in events:
            if any(rule.matches(event) for rule in self.rules):
                alert = Alert(event=event, trace_id=trace_id, span_id=span_id)
                self._dispatch(alert)

    def _dispatch(self, alert: Alert) -> None:
        for sink in self.sinks:
            try:
                sink(alert)
            except Exception:
                _logger.warning("tracewarden alert sink failed", exc_info=True)
