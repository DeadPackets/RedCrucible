from __future__ import annotations

import logging
from pathlib import Path

from redcrucible.config import settings
from redcrucible.exceptions import ToolNotFoundError
from redcrucible.models.tool import ToolDefinition, ToolInfo

from .manifest import load_manifest

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Manages the catalog of known offensive tools.

    Tools are loaded from the YAML manifest and can be queried by name.
    The registry also tracks whether a pre-compiled base assembly is
    available in the cache directory.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def load(self, manifest_path: Path) -> None:
        """Load tools from the manifest file."""
        tools = load_manifest(manifest_path)
        self._tools = {t.name: t for t in tools}
        logger.info("Tool registry loaded: %s", ", ".join(self._tools.keys()))

    def get(self, name: str) -> ToolDefinition:
        """Get a tool definition by name.

        Raises:
            ToolNotFoundError: If the tool is not in the registry.
        """
        if name not in self._tools:
            raise ToolNotFoundError(name)
        return self._tools[name]

    def list_tools(self) -> list[ToolInfo]:
        """Return public info for all registered tools."""
        return [self._to_info(t) for t in self._tools.values()]

    def has(self, name: str) -> bool:
        return name in self._tools

    @property
    def names(self) -> list[str]:
        return list(self._tools.keys())

    def _to_info(self, tool: ToolDefinition) -> ToolInfo:
        cache_path = settings.assembly_cache_dir / tool.assembly_path
        return ToolInfo(
            name=tool.name,
            display_name=tool.display_name,
            description=tool.description,
            repo_url=tool.repo_url,
            target_framework=tool.target_framework,
            default_stages=[s.name for s in tool.default_stages],
            cached=cache_path.exists(),
        )


# Global registry instance
tool_registry = ToolRegistry()
