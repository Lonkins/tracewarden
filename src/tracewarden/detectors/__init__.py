"""Pluggable security-event detectors. Importing this package registers every
built-in; each is independently toggleable via DetectorToggles."""

# import for side effect: registers the built-in detectors
from tracewarden.detectors import (  # noqa: F401
    cost_loop,
    llm,
    memory_poisoning,
    pii,
    prompt_injection,
    scope,
    secrets,
    sequence,
    tool_poisoning,
)
from tracewarden.detectors.base import (
    Detector,
    DetectorFactory,
    ScanContext,
    build_detectors,
    register,
    registered_toggles,
)

__all__ = [
    "Detector",
    "DetectorFactory",
    "ScanContext",
    "build_detectors",
    "register",
    "registered_toggles",
]
