"""Pluggable security-event detectors. Built-ins register here as they are
imported; every one is independently toggleable via DetectorToggles."""

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
