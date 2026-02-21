from datetime import datetime

from pydantic import BaseModel, Field

from .enums import Architecture, BuildStatus, OutputFormat


class StageConfig(BaseModel):
    """Configuration for a single pipeline stage."""

    name: str = Field(description="Registered stage name")
    options: dict = Field(
        default_factory=dict, description="Stage-specific options"
    )


class BuildRequest(BaseModel):
    """Request to build an obfuscated artifact."""

    tool: str = Field(description="Tool name from the manifest (e.g. 'rubeus')")
    output_format: OutputFormat = Field(
        default=OutputFormat.EXE,
        description="Desired output format",
    )
    architecture: Architecture = Field(
        default=Architecture.X64,
        description="Target architecture",
    )
    stages: list[StageConfig] | None = Field(
        default=None,
        description="Custom stage chain. If omitted, uses the tool's default chain.",
    )
    tool_args: str | None = Field(
        default=None,
        description="Arguments baked into the tool (e.g. 'kerberoast' for Rubeus)",
    )

    model_config = {"json_schema_extra": {"examples": [
        {
            "tool": "rubeus",
            "output_format": "exe",
            "architecture": "x64",
            "stages": [
                {"name": "obfuscar", "options": {"rename": True, "encrypt_strings": True}},
            ],
        }
    ]}}


class BuildResponse(BaseModel):
    """Response after submitting a build."""

    build_id: str
    status: BuildStatus
    tool: str
    output_format: OutputFormat
    architecture: Architecture
    stages: list[str] = Field(description="Stage names in execution order")
    created_at: datetime
    download_url: str | None = Field(
        default=None,
        description="URL to download the artifact (available when status=completed)",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="When the artifact will be deleted",
    )
    error: str | None = Field(
        default=None,
        description="Error message if status=failed",
    )


class BuildSummary(BaseModel):
    """Lightweight build info returned in list endpoints."""

    build_id: str
    status: BuildStatus
    tool: str
    output_format: OutputFormat
    created_at: datetime
