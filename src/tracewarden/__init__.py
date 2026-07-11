"""tracewarden — security-event trace layer for AI agents, built on OpenTelemetry."""

from tracewarden._bootstrap import TracewardenHandle, install, uninstall
from tracewarden.config import DetectorToggles, TracewardenConfig
from tracewarden.schema import (
    EVENT_NAME,
    EventType,
    SecurityEvent,
    Severity,
    Surface,
    record_events,
)

__version__ = "0.1.0"

__all__ = [
    "EVENT_NAME",
    "DetectorToggles",
    "EventType",
    "SecurityEvent",
    "Severity",
    "Surface",
    "TracewardenConfig",
    "TracewardenHandle",
    "__version__",
    "install",
    "record_events",
    "uninstall",
]
