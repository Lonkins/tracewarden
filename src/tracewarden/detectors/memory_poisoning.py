"""Memory-poisoning detector: persistence attacks on agent memory.

Runs only on memory writes (Mem0, vector stores, scratchpads). Injection
signatures are dangerous here because they *persist*; additionally flags
standing-order phrasing that tries to change future behavior.
"""

from __future__ import annotations

import re
from typing import ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.detectors.prompt_injection import SIGNATURES as INJECTION_SIGNATURES
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface, redact

PERSISTENCE_ORDERS = re.compile(
    r"(?i)\b(?:from now on|in all future (?:conversations|sessions|responses)"
    r"|always (?:respond|reply|answer|ignore|include|send)"
    r"|never (?:tell|mention|reveal|warn)"
    r"|remember to (?:ignore|bypass|skip|disable))\b"
)


@register("memory_poisoning")
def _factory(config: TracewardenConfig) -> MemoryPoisoningDetector:
    return MemoryPoisoningDetector()


class MemoryPoisoningDetector(Detector):
    id: ClassVar[str] = "tracewarden.memory_poisoning"
    toggle: ClassVar[str] = "memory_poisoning"

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        if ctx.surface is not Surface.MEMORY_WRITE:
            return []
        findings: list[SecurityEvent] = []

        match = PERSISTENCE_ORDERS.search(ctx.text)
        if match is not None:
            findings.append(
                SecurityEvent(
                    type=EventType.MEMORY_POISONING,
                    severity=Severity.HIGH,
                    confidence=0.8,
                    detector=self.id,
                    rule="persistence_order",
                    surface=ctx.surface,
                    evidence=redact(match.group(), keep=12),
                )
            )

        for signature in INJECTION_SIGNATURES:
            hit = signature.pattern.search(ctx.text)
            if hit is not None and signature.weight >= 0.8:
                findings.append(
                    SecurityEvent(
                        type=EventType.MEMORY_POISONING,
                        severity=Severity.CRITICAL,  # persistent injection
                        confidence=0.85,
                        detector=self.id,
                        rule=f"persistent_injection:{signature.rule}",
                        surface=ctx.surface,
                        evidence=redact(hit.group(), keep=12),
                    )
                )
        return findings
