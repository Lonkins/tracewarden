"""PII detector: emails, phone numbers, credit cards (Luhn-gated), US SSNs.

Deliberately conservative — a trace backend full of false PII alarms trains
people to ignore it. See the detector catalog for tuning guidance.
"""

from __future__ import annotations

import re
from typing import ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors._text import luhn_valid
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.schema import EventType, SecurityEvent, Severity, redact

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# 13-19 digits allowing spaces/dashes between groups; validated with Luhn.
CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
US_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
# E.164-ish or separated national numbers with at least 10 digits.
PHONE = re.compile(r"(?<![\w.])\+?\d{1,3}[ .-]?\(?\d{2,4}\)?(?:[ .-]?\d{2,4}){2,3}(?![\w-])")


@register("pii")
def _factory(config: TracewardenConfig) -> PiiDetector:
    return PiiDetector()


class PiiDetector(Detector):
    id: ClassVar[str] = "tracewarden.pii"
    toggle: ClassVar[str] = "pii"

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        findings: list[SecurityEvent] = []

        def add(rule: str, value: str, severity: Severity, confidence: float) -> None:
            findings.append(
                SecurityEvent(
                    type=EventType.PII_LEAK,
                    severity=severity,
                    confidence=confidence,
                    detector=self.id,
                    rule=rule,
                    surface=ctx.surface,
                    evidence=redact(value),
                )
            )

        for match in EMAIL.finditer(ctx.text):
            add("email", match.group(), Severity.LOW, 0.9)
        for match in US_SSN.finditer(ctx.text):
            add("us_ssn", match.group(), Severity.HIGH, 0.9)
        for match in CARD_CANDIDATE.finditer(ctx.text):
            digits = re.sub(r"[ -]", "", match.group())
            if luhn_valid(digits):
                add("credit_card", digits, Severity.HIGH, 0.85)
        for match in PHONE.finditer(ctx.text):
            digits = re.sub(r"\D", "", match.group())
            if len(digits) >= 10:
                add("phone_number", match.group(), Severity.LOW, 0.5)
        return findings
