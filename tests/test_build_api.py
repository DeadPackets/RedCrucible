import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_list_tools(client: AsyncClient):
    resp = await client.get("/api/v1/tools")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    # Should have tools from tools.yml loaded via lifespan
    names = [t["name"] for t in data]
    assert "rubeus" in names


@pytest.mark.asyncio
async def test_get_tool(client: AsyncClient):
    resp = await client.get("/api/v1/tools/rubeus")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "rubeus"
    assert data["display_name"] == "Rubeus"


@pytest.mark.asyncio
async def test_get_unknown_tool_returns_404(client: AsyncClient):
    resp = await client.get("/api/v1/tools/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_build_without_cached_assembly(client: AsyncClient):
    """Build should fail gracefully when no base assembly is cached."""
    resp = await client.post(
        "/api/v1/build",
        json={
            "tool": "rubeus",
            "output_format": "exe",
            "architecture": "x64",
            "stages": [{"name": "passthrough", "options": {}}],
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "failed"
    assert "not cached" in data["error"]


@pytest.mark.asyncio
async def test_build_unknown_tool_returns_404(client: AsyncClient):
    resp = await client.post(
        "/api/v1/build",
        json={"tool": "nonexistent", "output_format": "exe", "architecture": "x64"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_stages(client: AsyncClient):
    resp = await client.get("/api/v1/tools/stages/available")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    names = [s["name"] for s in data]
    assert "passthrough" in names
