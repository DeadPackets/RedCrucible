"""dnlib-based assembly patcher stage.

Runs the AssemblyPatcher C# tool on a .NET assembly to:
- Randomize GUIDs (MVID, GuidAttribute) to defeat GUID-based YARA signatures
- Mutate IL opcode encodings to defeat byte-pattern-based YARA signatures

Requires .NET 8 SDK (uses ``dotnet run --project``).
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import tempfile
import uuid
from pathlib import Path

from redcrucible.exceptions import PipelineError, StageValidationError
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline.context import PipelineContext
from redcrucible.pipeline.stage import BaseStage

logger = logging.getLogger(__name__)

# Path to the AssemblyPatcher C# project (relative to repo root)
_ASSEMBLY_PATCHER_PROJECT = Path(__file__).parent.parent.parent / "tools" / "AssemblyPatcher"


def _find_assembly_patcher() -> tuple[str, list[str]]:
    """Locate the AssemblyPatcher tool.

    Returns (executable, base_args) suitable for subprocess_exec.
    Prefers a pre-built binary on PATH; falls back to ``dotnet run --project``.
    """
    # Option 1: pre-built binary on PATH
    binary = shutil.which("assembly-patcher")
    if binary:
        return (binary, [])

    # Option 2: dotnet run --project (development mode)
    dotnet = shutil.which("dotnet")
    if dotnet is None:
        home_dotnet = Path.home() / ".dotnet" / "dotnet"
        if home_dotnet.exists():
            dotnet = str(home_dotnet)

    if dotnet and _ASSEMBLY_PATCHER_PROJECT.exists():
        return (dotnet, ["run", "--project", str(_ASSEMBLY_PATCHER_PROJECT), "--"])

    raise PipelineError(
        "dnlib_patcher",
        f"AssemblyPatcher tool not found. Ensure .NET SDK is installed and "
        f"'{_ASSEMBLY_PATCHER_PROJECT}' exists.",
    )


class DnlibPatcherStage(BaseStage):
    """Post-obfuscation assembly patcher using dnlib.

    Options:
        randomize_guids (bool): Replace MVID and GuidAttribute values. Default: True
        mutate_il (bool): Replace short-form IL opcodes with long-form equivalents. Default: True
    """

    @property
    def name(self) -> str:
        return "dnlib_patcher"

    @property
    def description(self) -> str:
        return "Post-obfuscation patcher: randomize GUIDs, mutate IL byte patterns"

    def supported_input_types(self) -> list[ArtifactType]:
        return [ArtifactType.DOTNET_ASSEMBLY]

    def output_type(self) -> ArtifactType:
        return ArtifactType.DOTNET_ASSEMBLY

    def validate_options(self, options: dict) -> None:
        allowed = {"randomize_guids", "mutate_il"}
        unknown = set(options.keys()) - allowed
        if unknown:
            raise StageValidationError(
                self.name,
                f"Unknown options: {', '.join(sorted(unknown))}",
            )

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        exe, base_args = _find_assembly_patcher()

        randomize_guids = options.get("randomize_guids", True)
        mutate_il = options.get("mutate_il", True)

        work_dir = Path(tempfile.mkdtemp(prefix="redcrucible_dnlib_patcher_"))
        try:
            return await self._run(
                ctx, exe, base_args, work_dir,
                randomize_guids=randomize_guids,
                mutate_il=mutate_il,
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    async def _run(
        self,
        ctx: PipelineContext,
        exe: str,
        base_args: list[str],
        work_dir: Path,
        *,
        randomize_guids: bool,
        mutate_il: bool,
    ) -> PipelineContext:
        # Write input assembly
        input_path = work_dir / f"{ctx.tool_name}_{uuid.uuid4().hex[:8]}.exe"
        output_path = work_dir / f"{ctx.tool_name}_{uuid.uuid4().hex[:8]}_patched.exe"
        input_path.write_bytes(ctx.artifact)

        # Build command line
        tool_args = [str(input_path), str(output_path)]
        if randomize_guids:
            tool_args.append("--randomize-guids")
        if mutate_il:
            tool_args.append("--mutate-il")

        cmd = [exe] + base_args + tool_args

        logger.info(
            "Running AssemblyPatcher on %s (build %s): guids=%s, il=%s",
            ctx.tool_name, ctx.build_id, randomize_guids, mutate_il,
        )

        # Build environment with DOTNET_ROOT
        env = os.environ.copy()
        dotnet_root = Path.home() / ".dotnet"
        if dotnet_root.exists():
            env["DOTNET_ROOT"] = str(dotnet_root)
            env["PATH"] = f"{dotnet_root}:{dotnet_root / 'tools'}:{env.get('PATH', '')}"

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(work_dir),
            env=env,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            output = (stdout + stderr).decode(errors="replace")
            raise PipelineError(
                self.name,
                f"AssemblyPatcher exited with code {proc.returncode}: {output[:500]}",
            )

        if not output_path.exists():
            raise PipelineError(
                self.name,
                "AssemblyPatcher produced no output assembly",
            )

        input_size = input_path.stat().st_size
        ctx.artifact = output_path.read_bytes()
        ctx.artifact_type = self.output_type()

        logger.info(
            "AssemblyPatcher completed for build %s: %d -> %d bytes",
            ctx.build_id, input_size, len(ctx.artifact),
        )

        return ctx
