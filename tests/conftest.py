"""Pytest fixtures for ReconForge testing."""

import asyncio
from collections.abc import AsyncGenerator

import pytest

from reconforge.core.models import TargetScope
from reconforge.core.scope import ScopeManager


@pytest.fixture
def sample_scope() -> TargetScope:
    """Fixture providing a standard authorized lab scope."""
    return TargetScope(
        allowed_targets=["127.0.0.1", "10.0.0.0/24", "localhost"],
        excluded_targets=["10.0.0.254"],
        allowed_ports="21,22,80,443,8000-8080",
        allow_public_targets=False,
        allow_cloud_metadata=False,
        lab_mode=True,
    )


@pytest.fixture
def sample_scope_manager(sample_scope: TargetScope) -> ScopeManager:
    """Fixture providing a configured ScopeManager."""
    return ScopeManager(sample_scope)


@pytest.fixture
async def mock_tcp_server() -> AsyncGenerator[tuple[str, int], None]:
    """Start a local TCP server on an ephemeral port for testing connection handshakes."""

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        writer.write(b"OK\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    sockets = server.sockets
    assert sockets, "Server started with no sockets"
    port = sockets[0].getsockname()[1]

    yield "127.0.0.1", port

    server.close()
    await server.wait_closed()


@pytest.fixture
async def mock_hanging_server() -> AsyncGenerator[tuple[str, int], None]:
    """Start a local TCP server that accepts connections but never replies (simulating slow server)."""

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await asyncio.sleep(10.0)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    sockets = server.sockets
    assert sockets, "Server started with no sockets"
    port = sockets[0].getsockname()[1]

    yield "127.0.0.1", port

    server.close()
    await server.wait_closed()
