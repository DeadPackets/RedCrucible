from __future__ import annotations

import logging
from pathlib import Path

import yaml

from redcrucible.models.tool import ToolDefinition, ToolStageDefault

logger = logging.getLogger(__name__)


def load_manifest(path: Path) -> list[ToolDefinition]:
    """Load tool definitions from a YAML manifest file.

    Args:
        path: Path to the tools.yml file.

    Returns:
        List of validated ToolDefinition objects.

    Raises:
        FileNotFoundError: If the manifest file doesn't exist.
        ValueError: If the manifest is malformed.
    """
    if not path.exists():
        raise FileNotFoundError(f"Tool manifest not found: {path}")

    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict) or "tools" not in raw:
        raise ValueError(f"Invalid manifest format: expected 'tools' key in {path}")

    tools: list[ToolDefinition] = []
    for entry in raw["tools"]:
        default_stages = [
            ToolStageDefault(**s) for s in entry.pop("default_stages", [])
        ]
        tool = ToolDefinition(**entry, default_stages=default_stages)
        tools.append(tool)

    logger.info("Loaded %d tools from manifest: %s", len(tools), path)
    return tools
