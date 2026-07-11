from collections.abc import Iterator

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.conftest import RecordingScanner
from tracewarden.instrumentation.pydantic_ai import (
    instrument_pydantic_ai,
    uninstrument_pydantic_ai,
)
from tracewarden.schema import Surface


@pytest.fixture()
def instrumented() -> Iterator[None]:
    instrument_pydantic_ai()
    yield
    uninstrument_pydantic_ai()


def test_agent_run_sync_scanned(
    span_exporter: InMemorySpanExporter,
    recording_scanner: RecordingScanner,
    instrumented: None,
) -> None:
    from pydantic_ai import Agent
    from pydantic_ai.models.test import TestModel

    agent: Agent[None, str] = Agent(TestModel())
    result = agent.run_sync("summarize the incident")

    assert recording_scanner.texts(Surface.USER_PROMPT) == ["summarize the incident"]
    completions = recording_scanner.texts(Surface.COMPLETION)
    assert completions and completions[0] == str(result.output)
    assert any(s.name == "agent pydantic_ai" for s in span_exporter.get_finished_spans())


def test_uninstrument_restores_original() -> None:
    from pydantic_ai import Agent

    original = Agent.run
    instrument_pydantic_ai()
    assert Agent.run is not original
    uninstrument_pydantic_ai()
    assert Agent.run is original
