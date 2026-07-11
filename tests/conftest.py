from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field

import pytest
from opentelemetry import trace as trace_api
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Span
from opentelemetry.util._once import Once

from tracewarden import _hooks
from tracewarden.schema import Surface


@dataclass
class RecordingScanner:
    """Captures every scan() the instrumentation performs."""

    seen: list[tuple[Surface, str, dict[str, str | int | float | bool]]] = field(
        default_factory=list
    )

    def __call__(
        self, span: Span, surface: Surface, text: str, meta: Mapping[str, str | int | float | bool]
    ) -> None:
        self.seen.append((surface, text, dict(meta)))

    def texts(self, surface: Surface) -> list[str]:
        return [text for s, text, _ in self.seen if s is surface]


@pytest.fixture()
def recording_scanner() -> Iterator[RecordingScanner]:
    scanner = RecordingScanner()
    _hooks.register_scanner(scanner)
    yield scanner
    _hooks.clear_scanners()


@pytest.fixture()
def span_exporter(monkeypatch: pytest.MonkeyPatch) -> Iterator[InMemorySpanExporter]:
    """Fresh global TracerProvider exporting to memory, reset afterwards."""
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(trace_api, "_TRACER_PROVIDER", provider)
    monkeypatch.setattr(trace_api, "_TRACER_PROVIDER_SET_ONCE", Once())
    yield exporter
    provider.shutdown()
