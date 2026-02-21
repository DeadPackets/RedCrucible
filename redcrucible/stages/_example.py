"""Example pipeline stage demonstrating the BaseStage interface.

This file serves as a template for implementing new stages. It is NOT
registered in the pipeline and will not appear in the API.

To create a new stage:
    1. Copy this file to redcrucible/stages/your_stage.py
    2. Implement the abstract methods
    3. Register an instance in redcrucible/stages/__init__.py:

        from .your_stage import YourStage
        from redcrucible.pipeline import stage_registry
        stage_registry.register(YourStage())
"""

from __future__ import annotations

from redcrucible.exceptions import StageValidationError
from redcrucible.models.enums import ArtifactType
from redcrucible.pipeline.context import PipelineContext
from redcrucible.pipeline.stage import BaseStage


class ExampleObfuscatorStage(BaseStage):
    """Example: a hypothetical IL obfuscation stage."""

    @property
    def name(self) -> str:
        return "example_obfuscator"

    @property
    def description(self) -> str:
        return "Example stage that demonstrates the plugin interface"

    def supported_input_types(self) -> list[ArtifactType]:
        # This stage accepts .NET assemblies
        return [ArtifactType.DOTNET_ASSEMBLY]

    def output_type(self) -> ArtifactType:
        # It produces an obfuscated .NET assembly
        return ArtifactType.DOTNET_ASSEMBLY

    def validate_options(self, options: dict) -> None:
        allowed = {"rename", "encrypt_strings", "control_flow"}
        unknown = set(options.keys()) - allowed
        if unknown:
            raise StageValidationError(
                self.name,
                f"Unknown options: {', '.join(sorted(unknown))}",
            )

    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        # Real implementation would:
        # 1. Write ctx.artifact to a temp file
        # 2. Run the obfuscator CLI via asyncio.create_subprocess_exec
        # 3. Read back the obfuscated bytes
        # 4. Update ctx.artifact and ctx.artifact_type

        # Placeholder: pass through unchanged
        ctx.artifact_type = self.output_type()
        return ctx
