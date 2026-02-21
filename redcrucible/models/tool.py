from pydantic import BaseModel, Field


class ToolStageDefault(BaseModel):
    """Default stage configuration for a tool."""

    name: str
    options: dict = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    """Schema for a tool defined in the tools manifest."""

    name: str = Field(description="Unique tool identifier (e.g. 'rubeus')")
    display_name: str = Field(description="Human-readable name (e.g. 'Rubeus')")
    description: str = Field(default="")
    repo_url: str = Field(description="Git repository URL")
    branch: str = Field(default="main", description="Default branch to track")
    assembly_path: str = Field(
        description="Path to the pre-compiled base assembly relative to cache dir",
    )
    target_framework: str = Field(
        default="net48",
        description="Target .NET framework (e.g. net48, net6.0)",
    )
    default_stages: list[ToolStageDefault] = Field(
        default_factory=list,
        description="Default pipeline stages to apply when none specified",
    )


class ToolInfo(BaseModel):
    """Public-facing tool info returned by the API."""

    name: str
    display_name: str
    description: str
    repo_url: str
    target_framework: str
    default_stages: list[str] = Field(
        description="Names of the default pipeline stages",
    )
    cached: bool = Field(
        description="Whether a pre-compiled assembly is cached and ready",
    )
