"""``tracewarden.install()`` — one-line wiring into whatever OTel setup exists.

Augment, never replace: if the app (or Langfuse/Phoenix SDK setup) already
registered a TracerProvider, tracewarden only attaches to it. Only when no real
provider exists does it create one with an OTLP/HTTP exporter. See docs/adr/0002.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from tracewarden.config import TracewardenConfig

_DEFAULT_SERVICE_NAME = "tracewarden-app"


@dataclass
class TracewardenHandle:
    """What install() wired up. Keep it to shut down cleanly (tests, workers)."""

    provider: TracerProvider
    config: TracewardenConfig
    created_provider: bool
    _shutdown: bool = field(default=False, repr=False)

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        if self.created_provider:
            self.provider.shutdown()


_handle: TracewardenHandle | None = None


def install(
    *,
    service_name: str | None = None,
    endpoint: str | None = None,
    config: TracewardenConfig | None = None,
    tracer_provider: TracerProvider | None = None,
) -> TracewardenHandle:
    """Wire tracewarden into the process. Idempotent.

    - ``tracer_provider``: attach to this provider (explicit injection).
    - Otherwise, attach to the globally registered SDK provider if one exists.
    - Otherwise, create a provider + OTLP/HTTP exporter and register it globally.
    """
    global _handle
    if _handle is not None and not _handle._shutdown:
        return _handle

    cfg = config or TracewardenConfig.from_env()
    if service_name is not None or endpoint is not None:
        cfg = cfg.model_copy(
            update={
                "service_name": service_name or cfg.service_name,
                "endpoint": endpoint or cfg.endpoint,
            }
        )

    provider = tracer_provider
    created = False
    if provider is None:
        existing = trace.get_tracer_provider()
        if isinstance(existing, TracerProvider):
            provider = existing
        else:
            resource = Resource.create({"service.name": cfg.service_name or _DEFAULT_SERVICE_NAME})
            provider = TracerProvider(resource=resource)
            exporter = (
                OTLPSpanExporter(endpoint=f"{cfg.endpoint.rstrip('/')}/v1/traces")
                if cfg.endpoint
                else OTLPSpanExporter()
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            created = True

    _handle = TracewardenHandle(provider=provider, config=cfg, created_provider=created)
    return _handle


def uninstall() -> None:
    """Shut down what install() created and forget it. Mainly for tests."""
    global _handle
    if _handle is not None:
        _handle.shutdown()
        _handle = None
