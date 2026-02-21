from __future__ import annotations

from abc import ABC, abstractmethod

from redcrucible.models.enums import ArtifactType

from .context import PipelineContext


class BaseStage(ABC):
    """Abstract base class for all pipeline stages.

    Every transformation in the pipeline (obfuscation, shellcode conversion,
    loader wrapping, signing, etc.) implements this interface. The PipelineEngine
    chains stages together, feeding each stage's output to the next stage's input.

    To implement a new stage:
        1. Create a new file in redcrucible/stages/
        2. Subclass BaseStage
        3. Implement all abstract methods
        4. Register the stage in redcrucible/stages/__init__.py

    See redcrucible/stages/_example.py for a documented example.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique identifier for this stage (e.g. 'obfuscar', 'donut')."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this stage does."""
        ...

    @abstractmethod
    def supported_input_types(self) -> list[ArtifactType]:
        """Artifact types this stage can accept as input."""
        ...

    @abstractmethod
    def output_type(self) -> ArtifactType:
        """Artifact type this stage produces."""
        ...

    @abstractmethod
    async def execute(self, ctx: PipelineContext, options: dict) -> PipelineContext:
        """Execute the stage transformation.

        Args:
            ctx: The pipeline context containing the current artifact and metadata.
            options: Stage-specific configuration options from the build request.

        Returns:
            The updated pipeline context with the transformed artifact.

        Raises:
            PipelineError: If the stage encounters an unrecoverable error.
        """
        ...

    def validate_options(self, options: dict) -> None:
        """Validate stage-specific options before execution.

        Override this to enforce required options, check value ranges, etc.
        The default implementation accepts any options.

        Raises:
            StageValidationError: If options are invalid.
        """

    def __repr__(self) -> str:
        return f"<Stage:{self.name}>"
