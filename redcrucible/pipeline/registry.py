from __future__ import annotations

from redcrucible.exceptions import StageNotFoundError

from .stage import BaseStage


class StageRegistry:
    """Discovers and manages pipeline stage plugins.

    Stages register themselves here and the PipelineEngine looks them up
    by name when constructing a pipeline chain.
    """

    def __init__(self) -> None:
        self._stages: dict[str, BaseStage] = {}

    def register(self, stage: BaseStage) -> None:
        """Register a stage instance."""
        self._stages[stage.name] = stage

    def get(self, name: str) -> BaseStage:
        """Look up a stage by name.

        Raises:
            StageNotFoundError: If no stage with that name is registered.
        """
        if name not in self._stages:
            raise StageNotFoundError(name)
        return self._stages[name]

    def list_stages(self) -> list[BaseStage]:
        """Return all registered stages."""
        return list(self._stages.values())

    def has(self, name: str) -> bool:
        """Check if a stage is registered."""
        return name in self._stages

    @property
    def names(self) -> list[str]:
        return list(self._stages.keys())


# Global registry instance
stage_registry = StageRegistry()
