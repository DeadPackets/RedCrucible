import shutil
from pathlib import Path

import pytest

from redcrucible.models import StageConfig
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline import PipelineContext, PipelineEngine, stage_registry


SHARPKATZ_PATH = Path(__file__).parent.parent / "cache" / "assemblies" / "sharpkatz" / "SharpKatz.exe"


@pytest.fixture
def sharpkatz_bytes() -> bytes:
    if not SHARPKATZ_PATH.exists():
        pytest.skip("SharpKatz base assembly not cached")
    return SHARPKATZ_PATH.read_bytes()


@pytest.mark.asyncio
async def test_obfuscar_stage_is_registered():
    assert stage_registry.has("obfuscar")
    stage = stage_registry.get("obfuscar")
    assert stage.name == "obfuscar"
    assert ArtifactType.DOTNET_ASSEMBLY in stage.supported_input_types()


@pytest.mark.asyncio
async def test_obfuscar_produces_different_binary(sharpkatz_bytes: bytes):
    """Run Obfuscar on SharpKatz and verify the output differs."""
    if not shutil.which("obfuscar.console"):
        # Check dotnet tools path
        candidate = Path.home() / ".dotnet" / "tools" / "obfuscar.console"
        if not candidate.exists():
            pytest.skip("obfuscar.console not installed")

    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="sharpkatz",
        artifact=sharpkatz_bytes,
        artifact_type=ArtifactType.DOTNET_ASSEMBLY,
    )
    stages = [StageConfig(name="obfuscar", options={"rename": True, "encrypt_strings": True})]

    result = await engine.execute(ctx, stages)

    # Output should be valid bytes, different from input
    assert len(result.artifact) > 0
    assert result.artifact != sharpkatz_bytes
    assert result.artifact_hash != PipelineContext(artifact=sharpkatz_bytes).artifact_hash

    # Should still be a PE file (starts with MZ)
    assert result.artifact[:2] == b"MZ"

    # Stage results should be recorded
    assert len(result.stage_results) == 1
    assert result.stage_results[0].stage_name == "obfuscar"
