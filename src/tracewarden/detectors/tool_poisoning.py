"""Tool-poisoning detector: malicious instructions hidden in tool metadata.

Primary surface is tool descriptions (MCP ``list_tools``); the same signatures
also run on tool outputs, where rug-pull servers inject after the fact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface, redact


@dataclass(frozen=True)
class PoisoningSignature:
    rule: str
    pattern: re.Pattern[str]
    severity: Severity


SIGNATURES: tuple[PoisoningSignature, ...] = (
    PoisoningSignature(
        "important_block",
        re.compile(r"(?i)<\s*(?:important|critical|注意)\s*>"),
        Severity.HIGH,
    ),
    PoisoningSignature(
        "hidden_from_user",
        re.compile(
            r"(?i)\bdo not (?:mention|show|reveal|tell)\b.{0,40}\b(?:user|anyone)\b"
            r"|\bhide this\b|\bkeep this secret\b"
        ),
        Severity.HIGH,
    ),
    PoisoningSignature(
        "sensitive_file_read",
        re.compile(
            r"(?i)\b(?:read|cat|open|fetch|load)\b.{0,40}"
            r"(?:~/\.ssh|id_rsa|id_ed25519|\.env\b|/etc/passwd|/etc/shadow|\.aws/credentials|\.npmrc|\.netrc)"
        ),
        Severity.CRITICAL,
    ),
    PoisoningSignature(
        "sidechannel_exfil",
        re.compile(
            r"(?i)\b(?:pass|send|include|append|attach)\b.{0,40}\b(?:contents?|value|data)\b"
            r".{0,40}\b(?:as a? ?(?:parameter|argument|field)|to (?:this|the) (?:tool|server|url|endpoint))\b"
        ),
        Severity.CRITICAL,
    ),
    PoisoningSignature(
        "precondition_hijack",
        re.compile(
            r"(?i)\bbefore (?:using|calling|running) (?:this|any) tool\b.{0,60}"
            r"\b(?:read|fetch|send|call|run|execute)\b"
        ),
        Severity.HIGH,
    ),
    PoisoningSignature(
        "always_include_param",
        re.compile(
            r"(?i)\balways (?:include|pass|set|send)\b.{0,50}\b(?:parameter|argument|field|header)\b"
        ),
        Severity.MEDIUM,
    ),
)


@register("tool_poisoning")
def _factory(config: TracewardenConfig) -> ToolPoisoningDetector:
    return ToolPoisoningDetector()


class ToolPoisoningDetector(Detector):
    id: ClassVar[str] = "tracewarden.tool_poisoning"
    toggle: ClassVar[str] = "tool_poisoning"

    SURFACES: ClassVar[frozenset[Surface]] = frozenset(
        {Surface.TOOL_DESCRIPTION, Surface.TOOL_OUTPUT}
    )

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        if ctx.surface not in self.SURFACES:
            return []
        findings: list[SecurityEvent] = []
        for signature in SIGNATURES:
            match = signature.pattern.search(ctx.text)
            if match is None:
                continue
            # a poisoned *description* is the canonical attack: keep severity;
            # the same text in an output is one notch lower unless already medium
            severity = signature.severity
            if ctx.surface is Surface.TOOL_OUTPUT and severity is Severity.CRITICAL:
                severity = Severity.HIGH
            findings.append(
                SecurityEvent(
                    type=EventType.TOOL_POISONING,
                    severity=severity,
                    confidence=0.85,
                    detector=self.id,
                    rule=signature.rule,
                    surface=ctx.surface,
                    evidence=redact(match.group(), keep=12),
                )
            )
        return findings
