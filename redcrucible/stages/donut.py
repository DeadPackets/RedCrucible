"""Donut shellcode generation stage.

Converts a .NET assembly into position-independent shellcode using Donut.
The shellcode contains an embedded CLR hosting stub that bootstraps the
.NET runtime and executes the assembly in-memory.

Requires the ``donut`` CLI binary to be available on PATH.
Build from source: https://github.com/TheWover/donut
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

_DONUT_CMD = "donut"

# Donut CLI flag mappings
_ARCH_MAP = {"x86": "1", "x64": "2", "x86+x64": "3"}
_BYPASS_MAP = {"none": "1", "abort": "2", "continue": "3"}
_EXIT_MAP = {"thread": "1", "process": "2", "block": "3"}


def _find_donut() -> str:
    """Locate the donut CLI binary."""
    path = shutil.which(_DONUT_CMD)
    if path:
        return path

    for candidate in [
        Path("/usr/local/bin") / _DONUT_CMD,
        Path.home() / ".local" / "bin" / _DONUT_CMD,
    ]:
        if candidate.exists():
            return str(candidate)

    raise PipelineError(
        "donut",
        f"'{_DONUT_CMD}' not found on PATH. "
        f"Build from source: https://github.com/TheWover/donut",
    )


class DonutStage(BaseStage):
    """Convert a .NET assembly to position-independent shellcode using Donut.

    Options:
        arch (str): Target architecture — "x86", "x64" (default), or "x86+x64".
        bypass (str): AMSI/WLDP/ETW bypass — "none", "abort", or "continue" (default).
        entropy (int): Entropy level — 1=none, 2=random names, 3=random+encrypt (default).
        exit_action (str): Exit behaviour — "thread" (default), "process", or "block".
        headers (str): PE headers — "overwrite" (default) or "keep".
        params (str): Arguments to pass to the .NET assembly at runtime.
        class_name (str): Class name for .NET DLL (optional for EXE).
        method (str): Method name for .NET DLL (optional for EXE).
    """

    @property
    def name(self) -> str:
        return "donut"

    @property
    def description(self) -> str:
        return "Convert .NET assembly to position-independent shellcode"

    def supported_input_types(self) -> list[ArtifactType]:
        return [ArtifactType.DOTNET_ASSEMBLY]

    def output_type(self) -> ArtifactType:
        return ArtifactType.SHELLCODE

    def validate_options(self, options: dict) -> None:
        allowed = {
            "arch", "bypass", "entropy", "exit_action", "headers",
            "params", "class_name", "method",
        }
        unknown = set(options.keys()) - allowed
        if unknown:
            raise StageValidationError(
                self.name,
                f"Unknown options: {', '.join(sorted(unknown))}",
            )

        if "arch" in options and options["arch"] not in _ARCH_MAP:
            raise StageValidationError(
                self.name,
                f"Invalid arch '{options['arch']}'. Must be one of: {', '.join(_ARCH_MAP)}",
            )
        if "bypass" in options and options["bypass"] not in _BYPASS_MAP:
            raise StageValidationError(
                self.name,
                f"Invalid bypass '{options['bypass']}'. Must be one of: {', '.join(_BYPASS_MAP)}",
            )
        if "entropy" in options and options["entropy"] not in (1, 2, 3):
            raise StageValidationError(
                self.name,
                f"Invalid entropy '{options['entropy']}'. Must be 1, 2, or 3.",
            )
        if "exit_action" in options and options["exit_action"] not in _EXIT_MAP:
            raise StageValidationError(
                self.name,
                f"Invalid exit_action '{options['exit_action']}'. Must be one of: {', '.join(_EXIT_MAP)}",
            )

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        donut_bin = _find_donut()

        work_dir = Path(tempfile.mkdtemp(prefix="redcrucible_donut_"))
        try:
            return await self._run(ctx, donut_bin, work_dir, options)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    async def _run(
        self,
        ctx: PipelineContext,
        donut_bin: str,
        work_dir: Path,
        options: dict,
    ) -> PipelineContext:
        # Write input assembly
        input_path = work_dir / f"{ctx.tool_name}_{uuid.uuid4().hex[:8]}.exe"
        output_path = work_dir / "loader.bin"
        input_path.write_bytes(ctx.artifact)

        # Build command line
        arch = _ARCH_MAP.get(options.get("arch", "x64"), "2")
        bypass = _BYPASS_MAP.get(options.get("bypass", "continue"), "3")
        entropy = str(options.get("entropy", 3))
        exit_action = _EXIT_MAP.get(options.get("exit_action", "thread"), "1")
        headers = "1" if options.get("headers", "overwrite") == "overwrite" else "2"

        cmd = [
            donut_bin,
            "-i", str(input_path),
            "-o", str(output_path),
            "-a", arch,
            "-b", bypass,
            "-e", entropy,
            "-x", exit_action,
            "-k", headers,
            "-f", "1",  # binary output
        ]

        # Optional .NET params
        params = options.get("params")
        if params:
            cmd.extend(["-p", params])

        class_name = options.get("class_name")
        if class_name:
            cmd.extend(["-c", class_name])

        method = options.get("method")
        if method:
            cmd.extend(["-m", method])

        logger.info(
            "Running Donut on %s (build %s): arch=%s, bypass=%s, entropy=%s",
            ctx.tool_name, ctx.build_id,
            options.get("arch", "x64"),
            options.get("bypass", "continue"),
            entropy,
        )

        env = os.environ.copy()

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
                f"Donut exited with code {proc.returncode}: {output[:500]}",
            )

        if not output_path.exists():
            raise PipelineError(
                self.name,
                "Donut produced no output file",
            )

        input_size = input_path.stat().st_size
        ctx.artifact = output_path.read_bytes()
        ctx.artifact_type = self.output_type()

        logger.info(
            "Donut completed for build %s: %d -> %d bytes (shellcode)",
            ctx.build_id, input_size, len(ctx.artifact),
        )

        return ctx
