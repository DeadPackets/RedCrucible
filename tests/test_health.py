import pytest
from httpx import ASGITransport, AsyncClient

from redcrucible import __version__
from redcrucible.main import app


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["version"] == __version__


@pytest.mark.asyncio
async def test_openapi_docs(client: AsyncClient):
    resp = await client.get("/docs")
    assert resp.status_code == 200
