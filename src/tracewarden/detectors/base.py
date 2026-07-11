"""Detector interface and registry.

A detector is a pure function of scan context → findings. Stateful detectors
(sequence, loop) keep their working data in ``ctx.trace_state``, a mutable
per-trace mapping the pipeline owns and prunes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

from tracewarden.config import DetectorToggles, TracewardenConfig
from tracewarden.schema import SecurityEvent, Surface


@dataclass(frozen=True)
class ScanContext:
    surface: Surface
    text: str
    meta: Mapping[str, str | int | float | bool] = field(default_factory=dict)
    # Per-trace scratch space, shared by all detectors across a trace's spans.
    # Namespaced by convention: detectors use keys prefixed with their id.
    trace_state: MutableMapping[str, Any] = field(default_factory=dict)

    @property
    def tool_name(self) -> str:
        value = self.meta.get("tool_name", "")
        return value if isinstance(value, str) else str(value)


class Detector(ABC):
    """One security-event detector. Implementations must be deterministic and
    local by default; anything network-bound is opt-in via config."""

    #: stable identifier, e.g. "tracewarden.secrets" — lands on the span event
    id: ClassVar[str]
    #: which DetectorToggles field enables this detector
    toggle: ClassVar[str]

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[SecurityEvent]: ...


DetectorFactory = Callable[[TracewardenConfig], Detector]

_REGISTRY: dict[str, DetectorFactory] = {}


def register(toggle: str) -> Callable[[DetectorFactory], DetectorFactory]:
    """Register a detector factory under a DetectorToggles field name."""
    if toggle not in DetectorToggles.model_fields:
        raise ValueError(f"Unknown detector toggle {toggle!r}")

    def decorator(factory: DetectorFactory) -> DetectorFactory:
        _REGISTRY[toggle] = factory
        return factory

    return decorator


def registered_toggles() -> frozenset[str]:
    return frozenset(_REGISTRY)


def build_detectors(config: TracewardenConfig) -> list[Detector]:
    """Instantiate every registered detector whose toggle is on."""
    toggles = config.detectors
    return [
        factory(config)
        for toggle, factory in sorted(_REGISTRY.items())
        if getattr(toggles, toggle, False)
    ]
