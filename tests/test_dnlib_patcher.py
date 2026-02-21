"""Tests for the dnlib_patcher pipeline stage."""

import shutil
from pathlib import Path

import pytest

from redcrucible.exceptions import StageValidationError
from redcrucible.models import StageConfig
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline import PipelineContext, PipelineEngine, stage_registry

SHARPKATZ_PATH = (
    Path(__file__).parent.parent / "cache" / "assemblies" / "sharpkatz" / "SharpKatz.exe"
)

ASSEMBLY_PATCHER_PROJECT = (
    Path(__file__).parent.parent / "tools" / "AssemblyPatcher" / "AssemblyPatcher.csproj"
)


@pytest.fixture
def sharpkatz_bytes() -> bytes:
    if not SHARPKATZ_PATH.exists():
        pytest.skip("SharpKatz base assembly not cached")
    return SHARPKATZ_PATH.read_bytes()


def _tool_available() -> bool:
    """Check if dotnet SDK and AssemblyPatcher project are available."""
    dotnet = shutil.which("dotnet")
    if not dotnet:
        candidate = Path.home() / ".dotnet" / "dotnet"
        if not candidate.exists():
            return False
    return ASSEMBLY_PATCHER_PROJECT.exists()


@pytest.mark.asyncio
async def test_dnlib_patcher_stage_is_registered():
    assert stage_registry.has("dnlib_patcher")
    stage = stage_registry.get("dnlib_patcher")
    assert stage.name == "dnlib_patcher"
    assert ArtifactType.DOTNET_ASSEMBLY in stage.supported_input_types()
    assert stage.output_type() == ArtifactType.DOTNET_ASSEMBLY


@pytest.mark.asyncio
async def test_dnlib_patcher_validates_options():
    stage = stage_registry.get("dnlib_patcher")
    # Valid options should not raise
    stage.validate_options({"randomize_guids": True, "mutate_il": False})
    stage.validate_options({})
    # Unknown option should raise
    with pytest.raises(StageValidationError):
        stage.validate_options({"unknown_option": True})


@pytest.mark.asyncio
async def test_dnlib_patcher_produces_different_binary(sharpkatz_bytes: bytes):
    """Run AssemblyPatcher on SharpKatz and verify the output differs."""
    if not _tool_available():
        pytest.skip("dotnet SDK or AssemblyPatcher project not available")

    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="sharpkatz",
        artifact=sharpkatz_bytes,
        artifact_type=ArtifactType.DOTNET_ASSEMBLY,
    )
    stages = [StageConfig(name="dnlib_patcher", options={
        "randomize_guids": True,
        "mutate_il": True,
    })]

    result = await engine.execute(ctx, stages)

    assert len(result.artifact) > 0
    assert result.artifact != sharpkatz_bytes
    assert result.artifact[:2] == b"MZ"
    assert len(result.stage_results) == 1
    assert result.stage_results[0].stage_name == "dnlib_patcher"


@pytest.mark.asyncio
async def test_dnlib_patcher_guid_removed(sharpkatz_bytes: bytes):
    """Verify the known SharpKatz GUID is no longer present after patching."""
    if not _tool_available():
        pytest.skip("dotnet SDK or AssemblyPatcher project not available")

    target_guid = b"8568b4c1-2940-4f6c-bf4e-4383ef268be9"
    assert target_guid in sharpkatz_bytes

    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="sharpkatz",
        artifact=sharpkatz_bytes,
        artifact_type=ArtifactType.DOTNET_ASSEMBLY,
    )
    stages = [StageConfig(name="dnlib_patcher", options={"randomize_guids": True})]

    result = await engine.execute(ctx, stages)

    # ASCII check
    assert target_guid not in result.artifact
    # Wide string (UTF-16LE) check
    wide_guid = target_guid.decode().encode("utf-16-le")
    assert wide_guid not in result.artifact


@pytest.mark.asyncio
async def test_full_pipeline_obfuscar_then_patcher(sharpkatz_bytes: bytes):
    """Run the full intended pipeline: obfuscar -> dnlib_patcher."""
    if not _tool_available():
        pytest.skip("dotnet SDK or AssemblyPatcher project not available")
    if not shutil.which("obfuscar.console"):
        candidate = Path.home() / ".dotnet" / "tools" / "obfuscar.console"
        if not candidate.exists():
            pytest.skip("obfuscar.console not installed")

    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="sharpkatz",
        artifact=sharpkatz_bytes,
        artifact_type=ArtifactType.DOTNET_ASSEMBLY,
    )
    stages = [
        StageConfig(name="obfuscar", options={"rename": True, "encrypt_strings": True}),
        StageConfig(name="dnlib_patcher", options={"randomize_guids": True, "mutate_il": True}),
    ]

    result = await engine.execute(ctx, stages)

    assert len(result.artifact) > 0
    assert result.artifact[:2] == b"MZ"
    assert len(result.stage_results) == 2
    assert result.stage_results[0].stage_name == "obfuscar"
    assert result.stage_results[1].stage_name == "dnlib_patcher"
