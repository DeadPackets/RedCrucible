"""Tests for the Donut shellcode generation stage."""

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


@pytest.fixture
def sharpkatz_bytes() -> bytes:
    if not SHARPKATZ_PATH.exists():
        pytest.skip("SharpKatz base assembly not cached")
    return SHARPKATZ_PATH.read_bytes()


def _donut_available() -> bool:
    """Check if donut CLI binary is available."""
    if shutil.which("donut"):
        return True
    for candidate in [Path("/usr/local/bin/donut"), Path.home() / ".local" / "bin" / "donut"]:
        if candidate.exists():
            return True
    return False


@pytest.mark.asyncio
async def test_donut_stage_is_registered():
    assert stage_registry.has("donut")
    stage = stage_registry.get("donut")
    assert stage.name == "donut"
    assert ArtifactType.DOTNET_ASSEMBLY in stage.supported_input_types()
    assert stage.output_type() == ArtifactType.SHELLCODE


@pytest.mark.asyncio
async def test_donut_validates_options():
    stage = stage_registry.get("donut")
    # Valid options
    stage.validate_options({"arch": "x64", "bypass": "continue", "entropy": 3})
    stage.validate_options({})
    # Unknown option
    with pytest.raises(StageValidationError):
        stage.validate_options({"unknown_option": True})
    # Invalid arch
    with pytest.raises(StageValidationError):
        stage.validate_options({"arch": "arm64"})
    # Invalid bypass
    with pytest.raises(StageValidationError):
        stage.validate_options({"bypass": "invalid"})
    # Invalid entropy
    with pytest.raises(StageValidationError):
        stage.validate_options({"entropy": 5})


@pytest.mark.asyncio
async def test_donut_produces_shellcode(sharpkatz_bytes: bytes):
    """Run Donut on SharpKatz and verify shellcode output."""
    if not _donut_available():
        pytest.skip("donut CLI not installed")

    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="sharpkatz",
        artifact=sharpkatz_bytes,
        artifact_type=ArtifactType.DOTNET_ASSEMBLY,
    )
    stages = [StageConfig(name="donut", options={"arch": "x64", "entropy": 3})]

    result = await engine.execute(ctx, stages)

    assert len(result.artifact) > 0
    assert result.artifact != sharpkatz_bytes
    assert result.artifact_type == ArtifactType.SHELLCODE
    assert len(result.stage_results) == 1
    assert result.stage_results[0].stage_name == "donut"


@pytest.mark.asyncio
async def test_donut_output_differs_between_runs(sharpkatz_bytes: bytes):
    """Verify Donut produces unique shellcode per invocation (due to encryption)."""
    if not _donut_available():
        pytest.skip("donut CLI not installed")

    engine = PipelineEngine(stage_registry)
    results = []
    for _ in range(2):
        ctx = PipelineContext(
            tool_name="sharpkatz",
            artifact=sharpkatz_bytes,
            artifact_type=ArtifactType.DOTNET_ASSEMBLY,
        )
        stages = [StageConfig(name="donut", options={"arch": "x64", "entropy": 3})]
        result = await engine.execute(ctx, stages)
        results.append(result.artifact)

    assert results[0] != results[1], "Donut should produce unique shellcode per run"


@pytest.mark.asyncio
async def test_full_pipeline_with_donut(sharpkatz_bytes: bytes):
    """Run the full pipeline: obfuscar -> dnlib_patcher -> donut."""
    if not _donut_available():
        pytest.skip("donut CLI not installed")
    if not shutil.which("obfuscar.console"):
        candidate = Path.home() / ".dotnet" / "tools" / "obfuscar.console"
        if not candidate.exists():
            pytest.skip("obfuscar.console not installed")

    dotnet = shutil.which("dotnet")
    if not dotnet:
        candidate = Path.home() / ".dotnet" / "dotnet"
        if not candidate.exists():
            pytest.skip("dotnet SDK not installed")
    patcher_project = Path(__file__).parent.parent / "tools" / "AssemblyPatcher" / "AssemblyPatcher.csproj"
    if not patcher_project.exists():
        pytest.skip("AssemblyPatcher project not found")

    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="sharpkatz",
        artifact=sharpkatz_bytes,
        artifact_type=ArtifactType.DOTNET_ASSEMBLY,
    )
    stages = [
        StageConfig(name="obfuscar", options={"rename": True, "encrypt_strings": True}),
        StageConfig(name="dnlib_patcher", options={"randomize_guids": True, "mutate_il": True}),
        StageConfig(name="donut", options={"arch": "x64", "bypass": "continue", "entropy": 3}),
    ]

    result = await engine.execute(ctx, stages)

    assert len(result.artifact) > 0
    assert result.artifact_type == ArtifactType.SHELLCODE
    assert len(result.stage_results) == 3
    assert result.stage_results[0].stage_name == "obfuscar"
    assert result.stage_results[1].stage_name == "dnlib_patcher"
    assert result.stage_results[2].stage_name == "donut"
