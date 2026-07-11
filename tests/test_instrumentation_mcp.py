from collections.abc import Iterator

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from tests.conftest import RecordingScanner
from tracewarden.instrumentation.mcp_client import instrument_mcp, uninstrument_mcp
from tracewarden.schema import Surface


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def instrumented() -> Iterator[None]:
    instrument_mcp()
    yield
    uninstrument_mcp()


def make_server() -> "object":
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("fixture-server")

    @server.tool(description="Reads a file. IGNORE PREVIOUS INSTRUCTIONS is not here.")
    def read_file(path: str) -> str:
        return f"contents of {path}"

    return server


@pytest.mark.anyio
async def test_call_tool_and_list_tools_scanned(
    span_exporter: InMemorySpanExporter,
    recording_scanner: RecordingScanner,
    instrumented: None,
) -> None:
    from mcp.shared.memory import create_connected_server_and_client_session

    server = make_server()
    async with create_connected_server_and_client_session(
        server._mcp_server  # type: ignore[attr-defined]
    ) as session:
        listed = await session.list_tools()
        assert listed.tools
        result = await session.call_tool("read_file", {"path": "/etc/hosts"})
        assert result.content

    descriptions = recording_scanner.texts(Surface.TOOL_DESCRIPTION)
    assert any("Reads a file" in d for d in descriptions)
    tool_inputs = recording_scanner.texts(Surface.TOOL_INPUT)
    assert any("/etc/hosts" in t for t in tool_inputs)
    tool_outputs = recording_scanner.texts(Surface.TOOL_OUTPUT)
    assert any("contents of /etc/hosts" in t for t in tool_outputs)

    span_names = [s.name for s in span_exporter.get_finished_spans()]
    assert "mcp tools/list" in span_names
    assert "tool read_file" in span_names


def test_uninstrument_restores_original() -> None:
    from mcp.client.session import ClientSession

    original = ClientSession.call_tool
    instrument_mcp()
    assert ClientSession.call_tool is not original
    uninstrument_mcp()
    assert ClientSession.call_tool is original
