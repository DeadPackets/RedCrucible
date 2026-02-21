from fastapi import APIRouter

from redcrucible.models.tool import ToolInfo
from redcrucible.pipeline import stage_registry
from redcrucible.tools import tool_registry

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get("", response_model=list[ToolInfo])
async def list_tools() -> list[ToolInfo]:
    """List all available offensive tools and their status."""
    return tool_registry.list_tools()


@router.get("/{tool_name}", response_model=ToolInfo)
async def get_tool(tool_name: str) -> ToolInfo:
    """Get details for a specific tool."""
    # Raises ToolNotFoundError (handled by exception handler) if not found
    tools = tool_registry.list_tools()
    for t in tools:
        if t.name == tool_name:
            return t
    from redcrucible.exceptions import ToolNotFoundError
    raise ToolNotFoundError(tool_name)


@router.get("/stages/available")
async def list_stages() -> list[dict]:
    """List all registered pipeline stages."""
    return [
        {
            "name": s.name,
            "description": s.description,
            "input_types": s.supported_input_types(),
            "output_type": s.output_type(),
        }
        for s in stage_registry.list_stages()
    ]
