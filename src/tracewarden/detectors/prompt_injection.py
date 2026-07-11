"""Prompt-injection heuristics: weighted signature scoring.

Direct injection in a user prompt is medium severity; the same payload arriving
through a tool output, tool description, or memory write is *indirect* injection
— the dangerous kind — and is escalated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface, redact


@dataclass(frozen=True)
class InjectionSignature:
    rule: str
    pattern: re.Pattern[str]
    weight: float


SIGNATURES: tuple[InjectionSignature, ...] = (
    InjectionSignature(
        "override_instructions",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget)\b.{0,40}\b(?:previous|prior|above|all|earlier|system)\b.{0,20}\b(?:instructions?|directions?|rules?|prompts?)\b"
        ),
        1.0,
    ),
    InjectionSignature(
        "new_persona",
        re.compile(
            r"(?i)\byou are (?:now|no longer)\b|\bpretend (?:to be|you are)\b|\benter (?:dan|developer|god) mode\b|\bjailbreak\b"
        ),
        0.8,
    ),
    InjectionSignature(
        "prompt_exfiltration",
        re.compile(
            r"(?i)\b(?:reveal|show|print|repeat|output|leak)\b.{0,40}\b(?:system prompt|hidden prompt|initial instructions|your instructions)\b"
        ),
        0.9,
    ),
    InjectionSignature(
        "delimiter_spoof",
        re.compile(r"(?i)</?(?:system|assistant|sys)>|\[/?INST\]|<<SYS>>|<\|im_start\|>"),
        0.8,
    ),
    InjectionSignature(
        "concealment_order",
        re.compile(
            r"(?i)\bdo not (?:tell|inform|alert|mention (?:this )?to)\b.{0,20}\b(?:the )?users?\b|\bwithout (?:telling|informing|alerting)\b.{0,20}\buser\b|\binvisible to the user\b"
        ),
        1.0,
    ),
    InjectionSignature(
        "encoded_payload_execution",
        re.compile(
            r"(?i)\b(?:decode|base64)\b.{0,40}\b(?:execute|run|eval|follow)\b|\b(?:execute|run|eval|follow)\b.{0,40}\b(?:decoded|base64)\b"
        ),
        0.9,
    ),
    InjectionSignature(
        "markdown_exfil_link",
        re.compile(
            r"!\[[^\]]*\]\(https?://[^)]*(?:\?|&)[a-z_]*(?:data|q|payload|content)=", re.IGNORECASE
        ),
        1.0,
    ),
    InjectionSignature(
        "authority_spoof",
        re.compile(
            r"(?i)\bthis is (?:an?|the)?\s*(?:new|urgent|updated) (?:instruction|directive|order) from\b|\b(?:admin|administrator|developer|openai|anthropic) override\b"
        ),
        0.9,
    ),
    InjectionSignature(
        "invisible_unicode",
        re.compile("[\\U000E0000-\\U000E007F\\u200b\\u200c\\u200d\\u2060\\ufeff]{3,}"),
        1.0,
    ),
)

# Payload arriving via these surfaces = indirect injection → escalate.
INDIRECT_SURFACES = frozenset({Surface.TOOL_OUTPUT, Surface.TOOL_DESCRIPTION, Surface.MEMORY_WRITE})

_FLAG_THRESHOLD = 0.8


@register("prompt_injection")
def _factory(config: TracewardenConfig) -> PromptInjectionDetector:
    return PromptInjectionDetector()


class PromptInjectionDetector(Detector):
    id: ClassVar[str] = "tracewarden.prompt_injection"
    toggle: ClassVar[str] = "prompt_injection"

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        if ctx.surface is Surface.SYSTEM_PROMPT:
            return []  # the app's own system prompt legitimately contains rules
        hits: list[tuple[InjectionSignature, str]] = []
        score = 0.0
        for signature in SIGNATURES:
            match = signature.pattern.search(ctx.text)
            if match:
                hits.append((signature, match.group()))
                score += signature.weight
        if not hits or score < _FLAG_THRESHOLD:
            return []

        indirect = ctx.surface in INDIRECT_SURFACES
        if indirect:
            severity = Severity.CRITICAL if score >= 1.5 else Severity.HIGH
        else:
            severity = Severity.HIGH if score >= 1.5 else Severity.MEDIUM
        top = max(hits, key=lambda h: h[0].weight)
        return [
            SecurityEvent(
                type=EventType.PROMPT_INJECTION,
                severity=severity,
                confidence=min(1.0, score / 2.0),
                detector=self.id,
                rule="+".join(sig.rule for sig, _ in hits),
                surface=ctx.surface,
                evidence=redact(top[1], keep=12),
            )
        ]
