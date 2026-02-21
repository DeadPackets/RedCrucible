from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from redcrucible.models.enums import Architecture, ArtifactType, OutputFormat


@dataclass
class StageResult:
    """Record of a single stage execution."""

    stage_name: str
    duration_ms: float
    input_hash: str
    output_hash: str
    artifact_type: ArtifactType
    metadata: dict = field(default_factory=dict)


@dataclass
class PipelineContext:
    """Carries the artifact and metadata through the pipeline stages.

    Each stage receives the context, transforms the artifact bytes,
    and returns the updated context.
    """

    build_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    tool_name: str = ""
    artifact: bytes = b""
    artifact_type: ArtifactType = ArtifactType.DOTNET_ASSEMBLY
    output_format: OutputFormat = OutputFormat.EXE
    architecture: Architecture = Architecture.X64
    tool_args: str | None = None

    stage_results: list[StageResult] = field(default_factory=list)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    error: str | None = None

    @property
    def artifact_hash(self) -> str:
        """SHA-256 hash of the current artifact."""
        return hashlib.sha256(self.artifact).hexdigest()

    @property
    def total_duration_ms(self) -> float:
        return sum(r.duration_ms for r in self.stage_results)

    @property
    def stage_names(self) -> list[str]:
        return [r.stage_name for r in self.stage_results]
