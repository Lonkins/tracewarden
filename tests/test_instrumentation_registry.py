import pytest

from tracewarden.instrumentation import (
    FRAMEWORKS,
    MissingDependencyError,
    instrument,
    uninstrument_all,
)


def test_unknown_framework_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown framework"):
        instrument(["not_a_framework"])


def test_instrument_and_uninstrument_roundtrip() -> None:
    from openai.resources.chat import completions

    original = completions.Completions.create
    assert instrument(["openai"]) == ["openai"]
    assert instrument(["openai"]) == ["openai"]  # idempotent
    assert completions.Completions.create is not original
    uninstrument_all()
    assert completions.Completions.create is original


def test_missing_dependency_message() -> None:
    err = MissingDependencyError("openai", "openai")
    assert "tracewarden[openai]" in str(err)


def test_frameworks_registry_complete() -> None:
    assert {"openai", "anthropic", "langchain", "llamaindex", "pydantic_ai", "mcp"} == FRAMEWORKS
