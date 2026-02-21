from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from redcrucible import __version__
from redcrucible.api.router import api_router, health_router
from redcrucible.config import settings
from redcrucible.exceptions import (
    ArtifactExpiredError,
    ArtifactNotFoundError,
    IncompatibleStageError,
    PipelineError,
    RedCrucibleError,
    StageNotFoundError,
    StageValidationError,
    ToolNotFoundError,
)
from redcrucible.storage import artifact_store
from redcrucible.tools import tool_registry

logging.basicConfig(
    level=settings.log_level.upper(),
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


async def _artifact_cleanup_loop() -> None:
    """Periodically clean up expired artifacts."""
    while True:
        await asyncio.sleep(60)
        try:
            await artifact_store.cleanup_expired()
        except Exception:
            logger.exception("Artifact cleanup error")


@asynccontextmanager
async def lifespan(app: FastAPI):  # noqa: ARG001
    # Startup
    logger.info("RedCrucible v%s starting up", __version__)

    # Load tool manifest
    try:
        tool_registry.load(settings.tools_manifest)
    except FileNotFoundError:
        logger.warning(
            "Tool manifest not found at %s — starting with empty tool registry",
            settings.tools_manifest,
        )

    # Ensure artifact directory exists
    artifact_store.ensure_dir()

    # Import stages to trigger registration
    import redcrucible.stages  # noqa: F401

    logger.info(
        "Ready: %d tools, %d stages",
        len(tool_registry.names),
        len(__import__("redcrucible.pipeline", fromlist=["stage_registry"]).stage_registry.names),
    )

    # Start background cleanup task
    cleanup_task = asyncio.create_task(_artifact_cleanup_loop())

    yield

    # Shutdown
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    logger.info("RedCrucible shut down")


app = FastAPI(
    title="RedCrucible",
    description="On-demand offensive .NET assembly obfuscation API",
    version=__version__,
    lifespan=lifespan,
)

app.include_router(health_router)
app.include_router(api_router)


# Exception handlers

@app.exception_handler(ToolNotFoundError)
async def tool_not_found_handler(request: Request, exc: ToolNotFoundError) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": str(exc)})


@app.exception_handler(ArtifactNotFoundError)
async def artifact_not_found_handler(request: Request, exc: ArtifactNotFoundError) -> JSONResponse:
    return JSONResponse(status_code=404, content={"error": str(exc)})


@app.exception_handler(ArtifactExpiredError)
async def artifact_expired_handler(request: Request, exc: ArtifactExpiredError) -> JSONResponse:
    return JSONResponse(status_code=410, content={"error": str(exc)})


@app.exception_handler(StageNotFoundError)
async def stage_not_found_handler(request: Request, exc: StageNotFoundError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.exception_handler(StageValidationError)
async def stage_validation_handler(request: Request, exc: StageValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": str(exc)})


@app.exception_handler(IncompatibleStageError)
async def incompatible_stage_handler(request: Request, exc: IncompatibleStageError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"error": str(exc)})


@app.exception_handler(PipelineError)
async def pipeline_error_handler(request: Request, exc: PipelineError) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": str(exc)})


@app.exception_handler(RedCrucibleError)
async def general_error_handler(request: Request, exc: RedCrucibleError) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": str(exc)})
