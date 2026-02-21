from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter

from redcrucible.config import settings
from redcrucible.models import (
    BuildRequest,
    BuildResponse,
    BuildStatus,
    StageConfig,
)
from redcrucible.pipeline import PipelineContext, PipelineEngine, stage_registry
from redcrucible.storage import artifact_store
from redcrucible.tools import tool_registry

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/build", tags=["build"])


def _resolve_stages(request: BuildRequest) -> list[StageConfig]:
    """Determine the stage chain: use request stages or tool defaults."""
    if request.stages is not None:
        return request.stages

    tool = tool_registry.get(request.tool)
    return [
        StageConfig(name=s.name, options=s.options)
        for s in tool.default_stages
    ]


def _output_filename(build_id: str, request: BuildRequest) -> str:
    ext = request.output_format.value
    return f"{request.tool}_{build_id}.{ext}"


@router.post("", response_model=BuildResponse)
async def create_build(request: BuildRequest) -> BuildResponse:
    """Trigger a new build with the specified obfuscation pipeline."""
    tool = tool_registry.get(request.tool)
    stage_configs = _resolve_stages(request)

    # Load the base assembly from cache
    assembly_path = settings.assembly_cache_dir / tool.assembly_path
    if not assembly_path.exists():
        return BuildResponse(
            build_id="",
            status=BuildStatus.FAILED,
            tool=request.tool,
            output_format=request.output_format,
            architecture=request.architecture,
            stages=[sc.name for sc in stage_configs],
            created_at=datetime.now(timezone.utc),
            error=f"Base assembly not cached: {tool.assembly_path}. "
            f"Run the cache warmup first.",
        )

    base_assembly = assembly_path.read_bytes()

    # Build the pipeline context
    ctx = PipelineContext(
        tool_name=request.tool,
        artifact=base_assembly,
        output_format=request.output_format,
        architecture=request.architecture,
        tool_args=request.tool_args,
    )

    # Execute the pipeline
    engine = PipelineEngine(stage_registry)
    try:
        ctx = await engine.execute(ctx, stage_configs)
    except Exception as exc:
        logger.exception("Build %s failed", ctx.build_id)
        return BuildResponse(
            build_id=ctx.build_id,
            status=BuildStatus.FAILED,
            tool=request.tool,
            output_format=request.output_format,
            architecture=request.architecture,
            stages=[sc.name for sc in stage_configs],
            created_at=ctx.created_at,
            error=str(exc),
        )

    # Store the artifact
    filename = _output_filename(ctx.build_id, request)
    meta = await artifact_store.store(
        build_id=ctx.build_id,
        artifact=ctx.artifact,
        tool=request.tool,
        filename=filename,
        sha256=ctx.artifact_hash,
    )

    expires_at = datetime.fromtimestamp(meta.expires_at, tz=timezone.utc)

    return BuildResponse(
        build_id=ctx.build_id,
        status=BuildStatus.COMPLETED,
        tool=request.tool,
        output_format=request.output_format,
        architecture=request.architecture,
        stages=ctx.stage_names,
        created_at=ctx.created_at,
        download_url=f"/api/v1/artifacts/{ctx.build_id}",
        expires_at=expires_at,
    )
