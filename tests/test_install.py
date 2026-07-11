from collections.abc import Iterator

import pytest
from opentelemetry.sdk.trace import TracerProvider

import tracewarden
from tracewarden.config import TracewardenConfig


@pytest.fixture(autouse=True)
def clean_state() -> Iterator[None]:
    yield
    tracewarden.uninstall()


def test_install_attaches_to_injected_provider() -> None:
    provider = TracerProvider()
    handle = tracewarden.install(tracer_provider=provider)
    assert handle.provider is provider
    assert handle.created_provider is False


def test_install_is_idempotent() -> None:
    provider = TracerProvider()
    first = tracewarden.install(tracer_provider=provider)
    second = tracewarden.install(tracer_provider=TracerProvider())
    assert second is first


def test_install_after_uninstall_rewires() -> None:
    first = tracewarden.install(tracer_provider=TracerProvider())
    tracewarden.uninstall()
    second = tracewarden.install(tracer_provider=TracerProvider())
    assert second is not first


def test_overrides_land_in_config() -> None:
    handle = tracewarden.install(
        tracer_provider=TracerProvider(),
        service_name="svc",
        endpoint="http://collector:4318",
    )
    assert handle.config.service_name == "svc"
    assert handle.config.endpoint == "http://collector:4318"


def test_explicit_config_wins() -> None:
    cfg = TracewardenConfig(service_name="cfg-svc")
    handle = tracewarden.install(tracer_provider=TracerProvider(), config=cfg)
    assert handle.config.service_name == "cfg-svc"


def test_config_from_env_toggles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRACEWARDEN_DETECT_SECRETS", "false")
    monkeypatch.setenv("TRACEWARDEN_DETECT_LLM", "1")
    monkeypatch.setenv("OTEL_SERVICE_NAME", "env-svc")
    cfg = TracewardenConfig.from_env()
    assert cfg.detectors.secrets is False
    assert cfg.detectors.llm is True
    assert cfg.detectors.pii is True
    assert cfg.service_name == "env-svc"


def test_install_creates_global_provider_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Reset the OTel global so this test exercises the "no provider yet" path.
    from opentelemetry import trace
    from opentelemetry.util._once import Once

    monkeypatch.setattr(trace, "_TRACER_PROVIDER", None)
    monkeypatch.setattr(trace, "_TRACER_PROVIDER_SET_ONCE", Once())
    handle = tracewarden.install(endpoint="http://localhost:4318")
    assert handle.created_provider is True
    assert isinstance(trace.get_tracer_provider(), TracerProvider)
