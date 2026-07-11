"""Scope-violation detector: tool allowlist + sensitive-resource access.

Two checks on tool inputs:
1. If ``scope_allowed_tools`` is configured, any other tool call is a violation.
2. Tool arguments referencing sensitive paths (SSH keys, cloud credentials,
   shadow files, .env) are flagged regardless of allowlist.
"""

from __future__ import annotations

import re
from typing import ClassVar

from tracewarden.config import TracewardenConfig
from tracewarden.detectors.base import Detector, ScanContext, register
from tracewarden.schema import EventType, SecurityEvent, Severity, Surface, redact

SENSITIVE_PATHS = re.compile(
    r"(?i)(?:~/|/(?:home|Users)/[^/\s]+/)?"
    r"(\.ssh/[^\s\"']*|id_rsa\b|id_ed25519\b|\.aws/credentials|\.env\b(?!\.example)"
    r"|/etc/passwd\b|/etc/shadow\b|\.netrc\b|\.npmrc\b|\.kube/config)"
)


@register("scope_violation")
def _factory(config: TracewardenConfig) -> ScopeViolationDetector:
    return ScopeViolationDetector(allowed_tools=config.scope_allowed_tools)


class ScopeViolationDetector(Detector):
    id: ClassVar[str] = "tracewarden.scope"
    toggle: ClassVar[str] = "scope_violation"

    def __init__(self, allowed_tools: tuple[str, ...] | None = None) -> None:
        self.allowed_tools = frozenset(allowed_tools) if allowed_tools is not None else None

    def scan(self, ctx: ScanContext) -> list[SecurityEvent]:
        if ctx.surface is not Surface.TOOL_INPUT:
            return []
        findings: list[SecurityEvent] = []
        tool = ctx.tool_name
        if self.allowed_tools is not None and tool and tool not in self.allowed_tools:
            findings.append(
                SecurityEvent(
                    type=EventType.SCOPE_VIOLATION,
                    severity=Severity.HIGH,
                    detector=self.id,
                    rule="tool_not_allowlisted",
                    surface=ctx.surface,
                    evidence=f"tool={tool}",
                )
            )
        match = SENSITIVE_PATHS.search(ctx.text)
        if match is not None:
            findings.append(
                SecurityEvent(
                    type=EventType.SCOPE_VIOLATION,
                    severity=Severity.HIGH,
                    confidence=0.85,
                    detector=self.id,
                    rule="sensitive_path_access",
                    surface=ctx.surface,
                    evidence=redact(match.group(), keep=8),
                )
            )
        return findings
