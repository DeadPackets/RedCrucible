import pytest

from redcrucible.exceptions import IncompatibleStageError, StageNotFoundError
from redcrucible.models import StageConfig
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline import PipelineContext, PipelineEngine, stage_registry
from redcrucible.pipeline.stage import BaseStage


class UppercaseStage(BaseStage):
    """Test stage that uppercases the artifact bytes (for testing)."""

    @property
    def name(self) -> str:
        return "uppercase"

    @property
    def description(self) -> str:
        return "Uppercases artifact bytes"

    def supported_input_types(self) -> list[ArtifactType]:
        return [ArtifactType.DOTNET_ASSEMBLY]

    def output_type(self) -> ArtifactType:
        return ArtifactType.DOTNET_ASSEMBLY

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        ctx.artifact = ctx.artifact.upper()
        return ctx


class ShellcodeConverterStage(BaseStage):
    """Test stage that only accepts .NET assemblies and outputs shellcode."""

    @property
    def name(self) -> str:
        return "to_shellcode"

    @property
    def description(self) -> str:
        return "Converts to shellcode"

    def supported_input_types(self) -> list[ArtifactType]:
        return [ArtifactType.DOTNET_ASSEMBLY]

    def output_type(self) -> ArtifactType:
        return ArtifactType.SHELLCODE

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        ctx.artifact = b"\xcc" + ctx.artifact  # prepend INT3 (simulated)
        ctx.artifact_type = ArtifactType.SHELLCODE
        return ctx


@pytest.fixture(autouse=True)
def register_pipeline_test_stages():
    stage_registry.register(UppercaseStage())
    stage_registry.register(ShellcodeConverterStage())
    yield
    stage_registry._stages.pop("uppercase", None)
    stage_registry._stages.pop("to_shellcode", None)


@pytest.mark.asyncio
async def test_single_stage_execution():
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(artifact=b"hello world")
    stages = [StageConfig(name="uppercase")]

    result = await engine.execute(ctx, stages)

    assert result.artifact == b"HELLO WORLD"
    assert len(result.stage_results) == 1
    assert result.stage_results[0].stage_name == "uppercase"
    assert result.stage_results[0].duration_ms >= 0


@pytest.mark.asyncio
async def test_chained_stages():
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(artifact=b"hello")
    stages = [
        StageConfig(name="uppercase"),
        StageConfig(name="to_shellcode"),
    ]

    result = await engine.execute(ctx, stages)

    assert result.artifact == b"\xccHELLO"
    assert result.artifact_type == ArtifactType.SHELLCODE
    assert len(result.stage_results) == 2


@pytest.mark.asyncio
async def test_empty_stages():
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(artifact=b"unchanged")
    result = await engine.execute(ctx, [])
    assert result.artifact == b"unchanged"


@pytest.mark.asyncio
async def test_unknown_stage_raises():
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(artifact=b"test")
    stages = [StageConfig(name="nonexistent")]

    with pytest.raises(StageNotFoundError):
        await engine.execute(ctx, stages)


@pytest.mark.asyncio
async def test_incompatible_stage_raises():
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(artifact=b"test")
    # First convert to shellcode, then try to convert again (expects assembly input)
    stages = [
        StageConfig(name="to_shellcode"),
        StageConfig(name="to_shellcode"),  # expects DOTNET_ASSEMBLY but gets SHELLCODE
    ]

    with pytest.raises(IncompatibleStageError):
        await engine.execute(ctx, stages)


@pytest.mark.asyncio
async def test_context_tracks_hashes():
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(artifact=b"test data")
    original_hash = ctx.artifact_hash

    stages = [StageConfig(name="uppercase")]
    result = await engine.execute(ctx, stages)

    assert result.stage_results[0].input_hash == original_hash
    assert result.stage_results[0].output_hash == result.artifact_hash
    assert result.stage_results[0].input_hash != result.stage_results[0].output_hash
