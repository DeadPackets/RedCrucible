"""Obfuscar IL-level obfuscation stage.

Runs the Obfuscar CLI tool on a .NET assembly to perform:
- Symbol renaming (types, methods, fields, properties, events, parameters)
- String encryption (HideStrings)
- Unicode name mangling

Requires `obfuscar.console` to be available on PATH (installed via
`dotnet tool install --global Obfuscar.GlobalTool`).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import uuid
from pathlib import Path

from redcrucible.exceptions import PipelineError, StageValidationError
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline.context import PipelineContext
from redcrucible.pipeline.stage import BaseStage

logger = logging.getLogger(__name__)

# Default Obfuscar XML config template
_CONFIG_TEMPLATE = """\
<?xml version='1.0'?>
<Obfuscator>
  <Var name="InPath" value="{in_path}" />
  <Var name="OutPath" value="{out_path}" />
  <Var name="RenameProperties" value="{rename_properties}" />
  <Var name="RenameEvents" value="{rename_events}" />
  <Var name="RenameFields" value="{rename_fields}" />
  <Var name="HideStrings" value="{hide_strings}" />
  <Var name="UseUnicodeNames" value="{unicode_names}" />
  <Var name="HidePrivateApi" value="{hide_private_api}" />
  <Var name="KeepPublicApi" value="{keep_public_api}" />
  <Var name="ReuseNames" value="{reuse_names}" />
  <Module file="{assembly_filename}" />
</Obfuscator>
"""

# Obfuscar CLI binary name
_OBFUSCAR_CMD = "obfuscar.console"


def _find_obfuscar() -> str:
    """Locate the obfuscar.console binary."""
    path = shutil.which(_OBFUSCAR_CMD)
    if path:
        return path

    # Check common dotnet tool install locations
    home = Path.home()
    for candidate in [
        home / ".dotnet" / "tools" / _OBFUSCAR_CMD,
        Path("/usr/local/bin") / _OBFUSCAR_CMD,
    ]:
        if candidate.exists():
            return str(candidate)

    raise PipelineError(
        "obfuscar",
        f"'{_OBFUSCAR_CMD}' not found on PATH. "
        f"Install with: dotnet tool install --global Obfuscar.GlobalTool",
    )


class ObfuscarStage(BaseStage):
    """IL-level obfuscation using Obfuscar.

    Options:
        rename (bool): Rename types, methods, fields, properties. Default: True
        encrypt_strings (bool): Encrypt string literals. Default: True
        unicode_names (bool): Use Unicode characters for obfuscated names. Default: True
        hide_private_api (bool): Obfuscate private/internal API. Default: True
        keep_public_api (bool): Preserve public API names. Default: False
    """

    @property
    def name(self) -> str:
        return "obfuscar"

    @property
    def description(self) -> str:
        return "IL-level .NET obfuscation: symbol renaming, string encryption"

    def supported_input_types(self) -> list[ArtifactType]:
        return [ArtifactType.DOTNET_ASSEMBLY]

    def output_type(self) -> ArtifactType:
        return ArtifactType.DOTNET_ASSEMBLY

    def validate_options(self, options: dict) -> None:
        allowed = {
            "rename", "encrypt_strings", "unicode_names",
            "hide_private_api", "keep_public_api",
        }
        unknown = set(options.keys()) - allowed
        if unknown:
            raise StageValidationError(
                self.name,
                f"Unknown options: {', '.join(sorted(unknown))}",
            )

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        obfuscar_bin = _find_obfuscar()

        rename = options.get("rename", True)
        encrypt_strings = options.get("encrypt_strings", True)
        unicode_names = options.get("unicode_names", True)
        hide_private_api = options.get("hide_private_api", True)
        keep_public_api = options.get("keep_public_api", False)

        work_dir = Path(tempfile.mkdtemp(prefix="redcrucible_obfuscar_"))
        try:
            return await self._run(
                ctx, obfuscar_bin, work_dir,
                rename=rename,
                encrypt_strings=encrypt_strings,
                unicode_names=unicode_names,
                hide_private_api=hide_private_api,
                keep_public_api=keep_public_api,
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    async def _run(
        self,
        ctx: PipelineContext,
        obfuscar_bin: str,
        work_dir: Path,
        *,
        rename: bool,
        encrypt_strings: bool,
        unicode_names: bool,
        hide_private_api: bool,
        keep_public_api: bool,
    ) -> PipelineContext:
        in_dir = work_dir / "input"
        out_dir = work_dir / "output"
        in_dir.mkdir()
        out_dir.mkdir()

        # Write the assembly to the input directory
        assembly_filename = f"{ctx.tool_name}_{uuid.uuid4().hex[:8]}.exe"
        input_path = in_dir / assembly_filename
        input_path.write_bytes(ctx.artifact)

        # Generate the Obfuscar XML config
        b = lambda v: "true" if v else "false"  # noqa: E731
        config_xml = _CONFIG_TEMPLATE.format(
            in_path=str(in_dir),
            out_path=str(out_dir),
            assembly_filename=assembly_filename,
            rename_properties=b(rename),
            rename_events=b(rename),
            rename_fields=b(rename),
            hide_strings=b(encrypt_strings),
            unicode_names=b(unicode_names),
            hide_private_api=b(hide_private_api),
            keep_public_api=b(keep_public_api),
            reuse_names=b(True),
        )

        config_path = work_dir / "obfuscar.xml"
        config_path.write_text(config_xml)

        logger.info(
            "Running Obfuscar on %s (build %s): rename=%s, strings=%s",
            ctx.tool_name, ctx.build_id, rename, encrypt_strings,
        )

        # Build environment with DOTNET_ROOT
        import os
        env = os.environ.copy()
        dotnet_root = Path.home() / ".dotnet"
        if dotnet_root.exists():
            env["DOTNET_ROOT"] = str(dotnet_root)
            env["PATH"] = f"{dotnet_root}:{dotnet_root / 'tools'}:{env.get('PATH', '')}"

        # Run Obfuscar (cwd must be the input dir so Module file resolves correctly)
        proc = await asyncio.create_subprocess_exec(
            obfuscar_bin, str(config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(in_dir),
            env=env,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            output = (stdout + stderr).decode(errors="replace")
            raise PipelineError(
                self.name,
                f"Obfuscar exited with code {proc.returncode}: {output[:500]}",
            )

        # Read the obfuscated assembly
        output_path = out_dir / assembly_filename
        if not output_path.exists():
            # Obfuscar may use the original name
            candidates = list(out_dir.glob("*.exe")) + list(out_dir.glob("*.dll"))
            if not candidates:
                raise PipelineError(
                    self.name,
                    "Obfuscar produced no output assembly",
                )
            output_path = candidates[0]

        ctx.artifact = output_path.read_bytes()
        ctx.artifact_type = self.output_type()

        logger.info(
            "Obfuscar completed for build %s: %d -> %d bytes",
            ctx.build_id, input_path.stat().st_size, len(ctx.artifact),
        )

        return ctx
