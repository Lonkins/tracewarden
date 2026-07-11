"""tracewarden — security-event trace layer for AI agents, built on OpenTelemetry."""

from tracewarden._bootstrap import TracewardenHandle, install, uninstall
from tracewarden._hooks import register_scanner, scan
from tracewarden.alerting import (
    Alert,
    AlertManager,
    AlertRule,
    file_sink,
    stdout_sink,
    webhook_sink,
)
from tracewarden.config import DetectorToggles, TracewardenConfig
from tracewarden.export import annotate_for_backends
from tracewarden.manual import guarded_tool, llm_call, memory_write, tool_call
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
    "Alert",
    "AlertManager",
    "AlertRule",
    "DetectorToggles",
    "EventType",
    "SecurityEvent",
    "Severity",
    "Surface",
    "TracewardenConfig",
    "TracewardenHandle",
    "__version__",
    "annotate_for_backends",
    "file_sink",
    "guarded_tool",
    "install",
    "llm_call",
    "memory_write",
    "record_events",
    "register_scanner",
    "scan",
    "stdout_sink",
    "tool_call",
    "uninstall",
    "webhook_sink",
]
