class RedCrucibleError(Exception):
    """Base exception for all RedCrucible errors."""


class ToolNotFoundError(RedCrucibleError):
    """Raised when a requested tool is not in the manifest."""

    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        super().__init__(f"Tool not found: {tool_name}")


class ArtifactNotFoundError(RedCrucibleError):
    """Raised when a build artifact does not exist or has expired."""

    def __init__(self, build_id: str):
        self.build_id = build_id
        super().__init__(f"Artifact not found or expired: {build_id}")


class ArtifactExpiredError(ArtifactNotFoundError):
    """Raised when a build artifact has expired its TTL."""


class PipelineError(RedCrucibleError):
    """Raised when the build pipeline encounters an error."""

    def __init__(self, stage_name: str, detail: str):
        self.stage_name = stage_name
        self.detail = detail
        super().__init__(f"Pipeline failed at stage '{stage_name}': {detail}")


class StageNotFoundError(RedCrucibleError):
    """Raised when a requested pipeline stage is not registered."""

    def __init__(self, stage_name: str):
        self.stage_name = stage_name
        super().__init__(f"Stage not registered: {stage_name}")


class StageValidationError(RedCrucibleError):
    """Raised when stage configuration is invalid."""

    def __init__(self, stage_name: str, detail: str):
        self.stage_name = stage_name
        self.detail = detail
        super().__init__(f"Invalid config for stage '{stage_name}': {detail}")


class IncompatibleStageError(RedCrucibleError):
    """Raised when a stage cannot accept the artifact type from the previous stage."""

    def __init__(self, stage_name: str, expected: str, got: str):
        self.stage_name = stage_name
        super().__init__(
            f"Stage '{stage_name}' expects {expected} input but got {got}"
        )
