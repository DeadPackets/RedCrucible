from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from redcrucible.main import app
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline import stage_registry
from redcrucible.pipeline.context import PipelineContext
from redcrucible.pipeline.stage import BaseStage
from redcrucible.tools import tool_registry


class PassthroughStage(BaseStage):
    """Test stage that passes the artifact through unchanged."""

    @property
    def name(self) -> str:
        return "passthrough"

    @property
    def description(self) -> str:
        return "Test stage that passes data through unchanged"

    def supported_input_types(self) -> list[ArtifactType]:
        return list(ArtifactType)

    def output_type(self) -> ArtifactType:
        return ArtifactType.DOTNET_ASSEMBLY

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        return ctx


@pytest.fixture(autouse=True)
def register_test_stages():
    """Register test stages before each test, clean up after."""
    stage_registry.register(PassthroughStage())
    yield
    stage_registry._stages.pop("passthrough", None)


@pytest.fixture(autouse=True, scope="session")
def load_tools_manifest():
    """Load tools.yml and register stages so tests mirror app startup."""
    import redcrucible.stages  # noqa: F401 — triggers stage registration

    manifest = Path(__file__).parent.parent / "tools.yml"
    if manifest.exists():
        tool_registry.load(manifest)


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
