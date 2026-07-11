"""The enrichment pipeline: runs detectors over scanned content and attaches
findings to the live span.

Registered as the scanner behind ``tracewarden._hooks.scan``. Keeps two bounded
caches: accumulated findings per span (so summary attributes stay correct when
one span is scanned several times) and scratch state per trace (for sequence /
loop detectors).
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Callable, Mapping, MutableMapping
from typing import Any

from opentelemetry.trace import Span

from tracewarden.config import TracewardenConfig
from tracewarden.detectors.base import Detector, ScanContext, build_detectors
from tracewarden.schema import (
    EVENT_NAME,
    SPAN_EVENT_COUNT,
    SPAN_EVENT_TYPES,
    SPAN_MAX_SEVERITY,
    SecurityEvent,
    Surface,
)

# ponytail: plain OrderedDict LRU caps; real eviction policy if memory ever matters
_MAX_TRACKED_SPANS = 4096
_MAX_TRACKED_TRACES = 1024

OnEvents = Callable[[Span, list[SecurityEvent]], None]


class DetectionPipeline:
    """Callable matching the ``tracewarden._hooks.Scanner`` signature."""

    def __init__(
        self,
        detectors: list[Detector],
        on_events: OnEvents | None = None,
    ) -> None:
        self.detectors = detectors
        self._on_events = on_events
        self._span_events: OrderedDict[int, list[SecurityEvent]] = OrderedDict()
        self._trace_state: OrderedDict[int, MutableMapping[str, Any]] = OrderedDict()

    @classmethod
    def from_config(
        cls, config: TracewardenConfig, on_events: OnEvents | None = None
    ) -> DetectionPipeline:
        return cls(build_detectors(config), on_events=on_events)

    def __call__(
        self,
        span: Span,
        surface: Surface,
        text: str,
        meta: Mapping[str, str | int | float | bool],
    ) -> None:
        ctx = ScanContext(
            surface=surface,
            text=text,
            meta=meta,
            trace_state=self._state_for(span.get_span_context().trace_id),
        )
        findings: list[SecurityEvent] = []
        for detector in self.detectors:
            findings.extend(detector.scan(ctx))
        if findings:
            self._attach(span, findings)

    def _attach(self, span: Span, findings: list[SecurityEvent]) -> None:
        for event in findings:
            span.add_event(EVENT_NAME, attributes=event.otel_attributes())
        accumulated = self._events_for(span)
        accumulated.extend(findings)
        span.set_attribute(SPAN_EVENT_COUNT, len(accumulated))
        span.set_attribute(
            SPAN_MAX_SEVERITY,
            max(accumulated, key=lambda e: e.severity.rank).severity.value,
        )
        span.set_attribute(SPAN_EVENT_TYPES, sorted({e.type.value for e in accumulated}))
        if self._on_events is not None:
            self._on_events(span, findings)

    def _events_for(self, span: Span) -> list[SecurityEvent]:
        key = span.get_span_context().span_id
        if key not in self._span_events:
            self._span_events[key] = []
            if len(self._span_events) > _MAX_TRACKED_SPANS:
                self._span_events.popitem(last=False)
        else:
            self._span_events.move_to_end(key)
        return self._span_events[key]

    def _state_for(self, trace_id: int) -> MutableMapping[str, Any]:
        if trace_id not in self._trace_state:
            self._trace_state[trace_id] = {}
            if len(self._trace_state) > _MAX_TRACKED_TRACES:
                self._trace_state.popitem(last=False)
        else:
            self._trace_state.move_to_end(trace_id)
        return self._trace_state[trace_id]
