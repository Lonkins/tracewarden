"""tracewarden — security-event trace layer for AI agents, built on OpenTelemetry."""

from tracewarden._bootstrap import TracewardenHandle, install, uninstall
from tracewarden._hooks import register_scanner, scan
from tracewarden.config import DetectorToggles, TracewardenConfig
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
    "DetectorToggles",
    "EventType",
    "SecurityEvent",
    "Severity",
    "Surface",
    "TracewardenConfig",
    "TracewardenHandle",
    "__version__",
    "guarded_tool",
    "install",
    "llm_call",
    "memory_write",
    "record_events",
    "register_scanner",
    "scan",
    "tool_call",
    "uninstall",
]
