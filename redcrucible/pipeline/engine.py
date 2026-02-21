from __future__ import annotations

import logging
import time

from redcrucible.exceptions import IncompatibleStageError, PipelineError
from redcrucible.models import StageConfig

from .context import PipelineContext, StageResult
from .registry import StageRegistry

logger = logging.getLogger(__name__)


class PipelineEngine:
    """Orchestrates the execution of a chain of pipeline stages.

    The engine takes a list of stage configurations, resolves them from the
    registry, validates type compatibility between stages, and executes them
    in sequence. Each stage receives the PipelineContext from the previous
    stage and produces an updated context for the next.
    """

    def __init__(self, registry: StageRegistry) -> None:
        self._registry = registry

    async def execute(
        self, ctx: PipelineContext, stage_configs: list[StageConfig]
    ) -> PipelineContext:
        """Run the full pipeline.

        Args:
            ctx: Initial pipeline context with the base artifact loaded.
            stage_configs: Ordered list of stages to execute.

        Returns:
            Final pipeline context with the transformed artifact.

        Raises:
            PipelineError: If any stage fails.
            IncompatibleStageError: If artifact type doesn't match stage input.
            StageNotFoundError: If a stage name isn't registered.
        """
        if not stage_configs:
            logger.warning("Pipeline executed with no stages for build %s", ctx.build_id)
            return ctx

        logger.info(
            "Starting pipeline for build %s: %s",
            ctx.build_id,
            " -> ".join(sc.name for sc in stage_configs),
        )

        for stage_config in stage_configs:
            stage = self._registry.get(stage_config.name)

            # Validate artifact type compatibility
            supported = stage.supported_input_types()
            if ctx.artifact_type not in supported:
                raise IncompatibleStageError(
                    stage.name,
                    expected=", ".join(supported),
                    got=ctx.artifact_type,
                )

            # Validate stage options
            stage.validate_options(stage_config.options)

            # Execute
            input_hash = ctx.artifact_hash
            start = time.perf_counter()

            try:
                ctx = await stage.execute(ctx, stage_config.options)
            except PipelineError:
                raise
            except Exception as exc:
                raise PipelineError(stage.name, str(exc)) from exc

            duration_ms = (time.perf_counter() - start) * 1000

            # Record result
            result = StageResult(
                stage_name=stage.name,
                duration_ms=round(duration_ms, 2),
                input_hash=input_hash,
                output_hash=ctx.artifact_hash,
                artifact_type=ctx.artifact_type,
            )
            ctx.stage_results.append(result)

            logger.info(
                "Stage '%s' completed in %.1fms (build %s)",
                stage.name,
                duration_ms,
                ctx.build_id,
            )

        logger.info(
            "Pipeline completed for build %s: %d stages in %.1fms",
            ctx.build_id,
            len(ctx.stage_results),
            ctx.total_duration_ms,
        )

        return ctx
