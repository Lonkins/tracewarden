"""Runtime configuration. Env-driven, no paid services, everything local by default."""

from __future__ import annotations

import os

from pydantic import BaseModel, ConfigDict, Field

ENV_PREFIX = "TRACEWARDEN_"


class DetectorToggles(BaseModel):
    """Every detector is independently toggleable. Deterministic ones default on;
    the LLM-assisted path is opt-in (see llm_detector_url)."""

    model_config = ConfigDict(frozen=True)

    secrets: bool = True
    pii: bool = True
    prompt_injection: bool = True
    tool_poisoning: bool = True
    scope_violation: bool = True
    memory_poisoning: bool = True
    anomalous_sequence: bool = True
    cost_loop: bool = True
    llm: bool = False  # opt-in, local model only


class TracewardenConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    service_name: str | None = None
    # OTLP/HTTP base endpoint, e.g. "http://localhost:4318". None = let the OTel
    # SDK resolve OTEL_EXPORTER_OTLP_ENDPOINT / its default.
    endpoint: str | None = None
    detectors: DetectorToggles = Field(default_factory=DetectorToggles)
    # Local LLM backend (Ollama-compatible) for the opt-in classifier detector.
    llm_detector_url: str = "http://localhost:11434"
    llm_detector_model: str = "llama3.2:1b"

    # --- detector tuning (see docs: detector catalog) -------------------
    # Tools the agent is allowed to call. None = any tool allowed.
    scope_allowed_tools: tuple[str, ...] | None = None
    # Threshold for identical repeated calls before flagging a loop/repeat.
    repeat_threshold: int = Field(default=3, ge=2)
    # LLM calls in one trace before a cost anomaly fires.
    llm_call_budget: int = Field(default=25, ge=1)
    # Distinct tools in one trace before a fan-out anomaly fires.
    tool_fanout_threshold: int = Field(default=15, ge=2)

    @classmethod
    def from_env(cls) -> TracewardenConfig:
        def flag(name: str, default: bool) -> bool:
            raw = os.environ.get(f"{ENV_PREFIX}{name}")
            if raw is None:
                return default
            return raw.strip().lower() in ("1", "true", "yes", "on")

        defaults = DetectorToggles()
        toggles = DetectorToggles(
            secrets=flag("DETECT_SECRETS", defaults.secrets),
            pii=flag("DETECT_PII", defaults.pii),
            prompt_injection=flag("DETECT_PROMPT_INJECTION", defaults.prompt_injection),
            tool_poisoning=flag("DETECT_TOOL_POISONING", defaults.tool_poisoning),
            scope_violation=flag("DETECT_SCOPE_VIOLATION", defaults.scope_violation),
            memory_poisoning=flag("DETECT_MEMORY_POISONING", defaults.memory_poisoning),
            anomalous_sequence=flag("DETECT_ANOMALOUS_SEQUENCE", defaults.anomalous_sequence),
            cost_loop=flag("DETECT_COST_LOOP", defaults.cost_loop),
            llm=flag("DETECT_LLM", defaults.llm),
        )

        def integer(name: str, default: int) -> int:
            raw = os.environ.get(f"{ENV_PREFIX}{name}")
            return int(raw) if raw and raw.strip().isdigit() else default

        allowed_tools_raw = os.environ.get(f"{ENV_PREFIX}SCOPE_ALLOWED_TOOLS")
        allowed_tools = (
            tuple(t.strip() for t in allowed_tools_raw.split(",") if t.strip())
            if allowed_tools_raw
            else None
        )
        return cls(
            service_name=os.environ.get("OTEL_SERVICE_NAME"),
            endpoint=os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"),
            detectors=toggles,
            llm_detector_url=os.environ.get(
                f"{ENV_PREFIX}LLM_DETECTOR_URL", "http://localhost:11434"
            ),
            llm_detector_model=os.environ.get(f"{ENV_PREFIX}LLM_DETECTOR_MODEL", "llama3.2:1b"),
            scope_allowed_tools=allowed_tools,
            repeat_threshold=integer("REPEAT_THRESHOLD", 3),
            llm_call_budget=integer("LLM_CALL_BUDGET", 25),
            tool_fanout_threshold=integer("TOOL_FANOUT_THRESHOLD", 15),
        )
