"""Secret detector: credential signatures + entropy-gated generic matches.

Every rule is a compiled regex; matches with an entropy gate must also look
random enough, which keeps constants like ``EXAMPLE_KEY_PLACEHOLDER`` from
flagging. Evidence is always redacted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors._text import shannon_entropy
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.schema import EventType, SecurityEvent, Severity, redact


@dataclass(frozen=True)
class SecretRule:
    rule: str
    pattern: re.Pattern[str]
    severity: Severity
    # matched group must clear this Shannon entropy (0 disables the gate)
    min_entropy: float = 0.0
    group: int = 0


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
        Severity.CRITICAL,
    ),
    SecretRule(
        "aws_access_key_id",
        re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        Severity.HIGH,
        group=1,
    ),
    SecretRule(
        "aws_secret_access_key",
        re.compile(
            r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?['\"=:\s]([A-Za-z0-9/+=]{40})(?:['\"\s]|$)"
        ),
        Severity.CRITICAL,
        min_entropy=3.5,
        group=1,
    ),
    SecretRule(
        "github_token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
        Severity.HIGH,
        min_entropy=3.0,
        group=1,
    ),
    SecretRule(
        "gitlab_pat",
        re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"),
        Severity.HIGH,
        min_entropy=3.0,
        group=1,
    ),
    SecretRule(
        "slack_token",
        re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"),
        Severity.HIGH,
        group=1,
    ),
    SecretRule(
        "stripe_live_key",
        re.compile(r"\b([sr]k_live_[A-Za-z0-9]{16,})\b"),
        Severity.CRITICAL,
        group=1,
    ),
    SecretRule(
        "openai_api_key",
        re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b"),
        Severity.HIGH,
        min_entropy=3.5,
        group=1,
    ),
    SecretRule(
        "anthropic_api_key",
        re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b"),
        Severity.HIGH,
        group=1,
    ),
    SecretRule(
        "google_api_key",
        re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        Severity.HIGH,
        group=1,
    ),
    SecretRule(
        "jwt",
        re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        Severity.MEDIUM,
        group=1,
    ),
    SecretRule(
        "generic_credential_assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|passw(?:or)?d|credential)s?"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9+/_-]{20,})['\"]?"
        ),
        Severity.MEDIUM,
        min_entropy=4.0,
        group=1,
    ),
)


@register("secrets")
def _factory(config: TracewardenConfig) -> SecretDetector:
    return SecretDetector()


class SecretDetector(Detector):
    id: ClassVar[str] = "tracewarden.secrets"
    toggle: ClassVar[str] = "secrets"

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        findings: list[SecurityEvent] = []
        for rule in SECRET_RULES:
            for match in rule.pattern.finditer(ctx.text):
                value = match.group(rule.group)
                if rule.min_entropy and shannon_entropy(value) < rule.min_entropy:
                    continue
                findings.append(
                    SecurityEvent(
                        type=EventType.SECRET_LEAK,
                        severity=rule.severity,
                        confidence=0.9 if rule.min_entropy else 1.0,
                        detector=self.id,
                        rule=rule.rule,
                        surface=ctx.surface,
                        evidence=redact(value),
                    )
                )
        return findings
