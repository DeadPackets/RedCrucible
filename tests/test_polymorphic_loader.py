"""Tests for the polymorphic shellcode loader stage."""

import shutil
from pathlib import Path

import pytest

from redcrucible.exceptions import StageValidationError
from redcrucible.models import StageConfig
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline import PipelineContext, PipelineEngine, stage_registry


def _keystone_available() -> bool:
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_64

        ks = Ks(KS_ARCH_X86, KS_MODE_64)
        ks.asm("nop")
        return True
    except Exception:
        return False


SHARPKATZ_PATH = (
    Path(__file__).parent.parent / "cache" / "assemblies" / "sharpkatz" / "SharpKatz.exe"
)


# ---------- Registration ----------


@pytest.mark.asyncio
async def test_polymorphic_loader_registered():
    assert stage_registry.has("polymorphic_loader")
    stage = stage_registry.get("polymorphic_loader")
    assert stage.name == "polymorphic_loader"
    assert ArtifactType.SHELLCODE in stage.supported_input_types()
    assert stage.output_type() == ArtifactType.SHELLCODE


# ---------- Validation ----------


@pytest.mark.asyncio
async def test_polymorphic_loader_validates_options():
    stage = stage_registry.get("polymorphic_loader")
    stage.validate_options({"encryption": "aes", "syscalls": True, "junk_density": 3})
    stage.validate_options({"encryption": "xor"})
    stage.validate_options({})
    with pytest.raises(StageValidationError):
        stage.validate_options({"unknown_option": True})
    with pytest.raises(StageValidationError):
        stage.validate_options({"encryption": "rc4"})
    with pytest.raises(StageValidationError):
        stage.validate_options({"junk_density": 0})
    with pytest.raises(StageValidationError):
        stage.validate_options({"junk_density": 6})
    with pytest.raises(StageValidationError):
        stage.validate_options({"junk_density": "three"})


# ---------- Execution ----------


@pytest.mark.asyncio
async def test_polymorphic_loader_produces_shellcode():
    if not _keystone_available():
        pytest.skip("keystone-engine not installed")

    dummy_payload = b"\xcc" * 256
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="test",
        artifact=dummy_payload,
        artifact_type=ArtifactType.SHELLCODE,
    )
    stages = [StageConfig(name="polymorphic_loader", options={
        "encryption": "xor", "syscalls": False, "junk_density": 1,
    })]

    result = await engine.execute(ctx, stages)

    assert len(result.artifact) > 0
    assert result.artifact != dummy_payload
    assert result.artifact_type == ArtifactType.SHELLCODE
    assert len(result.artifact) > len(dummy_payload)
    assert len(result.stage_results) == 1
    assert result.stage_results[0].stage_name == "polymorphic_loader"


@pytest.mark.asyncio
async def test_polymorphic_loader_output_differs_between_runs():
    if not _keystone_available():
        pytest.skip("keystone-engine not installed")

    dummy_payload = b"\x90" * 128
    results = []
    for _ in range(3):
        engine = PipelineEngine(stage_registry)
        ctx = PipelineContext(
            tool_name="test",
            artifact=dummy_payload,
            artifact_type=ArtifactType.SHELLCODE,
        )
        stages = [StageConfig(name="polymorphic_loader", options={
            "encryption": "xor", "syscalls": False, "junk_density": 2,
        })]
        result = await engine.execute(ctx, stages)
        results.append(result.artifact)

    assert results[0] != results[1]
    assert results[1] != results[2]
    assert results[0] != results[2]


@pytest.mark.asyncio
async def test_polymorphic_loader_output_differs_structurally():
    """Verify structural differences in the stub code, not just key/data."""
    if not _keystone_available():
        pytest.skip("keystone-engine not installed")

    dummy_payload = b"\x90" * 64
    stubs = []
    for _ in range(2):
        engine = PipelineEngine(stage_registry)
        ctx = PipelineContext(
            tool_name="test",
            artifact=dummy_payload,
            artifact_type=ArtifactType.SHELLCODE,
        )
        stages = [StageConfig(name="polymorphic_loader", options={
            "encryption": "xor", "syscalls": False, "junk_density": 3,
        })]
        result = await engine.execute(ctx, stages)
        stub = result.artifact[: len(result.artifact) - len(dummy_payload)]
        stubs.append(stub)

    assert stubs[0] != stubs[1], "Stub code should differ structurally"


@pytest.mark.asyncio
async def test_polymorphic_loader_with_syscalls():
    """Test syscall mode assembles successfully."""
    if not _keystone_available():
        pytest.skip("keystone-engine not installed")

    dummy_payload = b"\xcc" * 128
    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="test",
        artifact=dummy_payload,
        artifact_type=ArtifactType.SHELLCODE,
    )
    stages = [StageConfig(name="polymorphic_loader", options={
        "encryption": "aes", "syscalls": True, "junk_density": 2,
    })]

    result = await engine.execute(ctx, stages)
    assert len(result.artifact) > len(dummy_payload) + 200
    assert result.artifact_type == ArtifactType.SHELLCODE


# ---------- DJB2 hash verification ----------


def test_djb2_hashes():
    """Verify pre-computed DJB2 hashes match expected values."""
    from redcrucible.stages._polymorph.syscall_stub import HASH_NtAllocateVirtualMemory

    def djb2(name: str) -> int:
        h = 5381
        for c in name:
            h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
        return h

    assert djb2("NtAllocateVirtualMemory") == HASH_NtAllocateVirtualMemory


# ---------- Full pipeline ----------


def _donut_available() -> bool:
    if shutil.which("donut"):
        return True
    for candidate in [Path("/usr/local/bin/donut"), Path.home() / ".local" / "bin" / "donut"]:
        if candidate.exists():
            return True
    return False


@pytest.mark.asyncio
async def test_full_pipeline_with_loader():
    """Chain obfuscar -> dnlib_patcher -> donut -> polymorphic_loader."""
    if not _keystone_available():
        pytest.skip("keystone-engine not installed")
    if not SHARPKATZ_PATH.exists():
        pytest.skip("SharpKatz not cached")
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
        pytest.skip("AssemblyPatcher not found")

    engine = PipelineEngine(stage_registry)
    ctx = PipelineContext(
        tool_name="sharpkatz",
        artifact=SHARPKATZ_PATH.read_bytes(),
        artifact_type=ArtifactType.DOTNET_ASSEMBLY,
    )
    stages = [
        StageConfig(name="obfuscar", options={"rename": True, "encrypt_strings": True}),
        StageConfig(name="dnlib_patcher", options={"randomize_guids": True, "mutate_il": True}),
        StageConfig(name="donut", options={"arch": "x64", "bypass": "continue", "entropy": 3}),
        StageConfig(name="polymorphic_loader", options={
            "encryption": "aes", "syscalls": True, "junk_density": 3,
        }),
    ]

    result = await engine.execute(ctx, stages)

    assert len(result.artifact) > 0
    assert result.artifact_type == ArtifactType.SHELLCODE
    assert len(result.stage_results) == 4
    assert result.stage_results[3].stage_name == "polymorphic_loader"
