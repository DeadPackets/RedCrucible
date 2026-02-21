from fastapi import APIRouter

from redcrucible import __version__
from redcrucible.pipeline import stage_registry
from redcrucible.tools import tool_registry

router = APIRouter()


@router.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "version": __version__,
        "tools_loaded": len(tool_registry.names),
        "stages_registered": len(stage_registry.names),
    }
