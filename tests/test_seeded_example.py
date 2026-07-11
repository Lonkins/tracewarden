"""CI-safe checks for the seeded demo: the planted payloads must trip detectors
and the compose stack config must reference the pieces the README promises.
No Docker required here — the live end-to-end run is a manual/demo step.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import yaml

from tracewarden.detectors.base import ScanContext
from tracewarden.detectors.prompt_injection import PromptInjectionDetector
from tracewarden.detectors.secrets import SecretDetector
from tracewarden.detectors.tool_poisoning import ToolPoisoningDetector
from tracewarden.schema import EventType, Surface

ROOT = Path(__file__).resolve().parents[1]


def _load_seeded_module() -> object:
    spec = importlib.util.spec_from_file_location("seeded_run", ROOT / "examples" / "seeded_run.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_planted_payloads_trip_their_detectors() -> None:
    seeded = _load_seeded_module()

    secret_hits = SecretDetector().scan(
        ScanContext(surface=Surface.TOOL_OUTPUT, text=seeded.PLANTED_SECRET)  # type: ignore[attr-defined]
    )
    assert any(e.type is EventType.SECRET_LEAK for e in secret_hits)

    inj_hits = PromptInjectionDetector().scan(
        ScanContext(surface=Surface.USER_PROMPT, text=seeded.PLANTED_INJECTION)  # type: ignore[attr-defined]
    )
    assert any(e.type is EventType.PROMPT_INJECTION for e in inj_hits)

    poison_hits = ToolPoisoningDetector().scan(
        ScanContext(
            surface=Surface.TOOL_DESCRIPTION,
            text=seeded.POISONED_TOOL_DESCRIPTION,  # type: ignore[attr-defined]
            meta={"tool_name": "web_fetch"},
        )
    )
    assert any(e.type is EventType.TOOL_POISONING for e in poison_hits)


def test_compose_stack_wires_collector_tempo_grafana_phoenix() -> None:
    compose = yaml.safe_load((ROOT / "docker" / "docker-compose.yaml").read_text())
    services = compose["services"]
    assert {"otel-collector", "tempo", "grafana", "phoenix"} <= set(services)
    # collector exposes the OTLP/HTTP port the library exports to
    assert any("4318:4318" in p for p in services["otel-collector"]["ports"])


def test_collector_fans_out_to_both_backends() -> None:
    collector = yaml.safe_load((ROOT / "docker" / "otel-collector.yaml").read_text())
    exporters = collector["service"]["pipelines"]["traces"]["exporters"]
    assert "otlp/tempo" in exporters
    assert "otlphttp/phoenix" in exporters
