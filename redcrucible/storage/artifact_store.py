from __future__ import annotations

import json
import logging
import time
from pathlib import Path

import aiofiles

from redcrucible.config import settings
from redcrucible.exceptions import ArtifactExpiredError, ArtifactNotFoundError

logger = logging.getLogger(__name__)


class ArtifactMeta:
    """Metadata sidecar for a stored artifact."""

    def __init__(
        self,
        build_id: str,
        tool: str,
        filename: str,
        sha256: str,
        size_bytes: int,
        created_at: float,
        ttl_seconds: int,
    ):
        self.build_id = build_id
        self.tool = tool
        self.filename = filename
        self.sha256 = sha256
        self.size_bytes = size_bytes
        self.created_at = created_at
        self.ttl_seconds = ttl_seconds

    @property
    def expires_at(self) -> float:
        return self.created_at + self.ttl_seconds

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "build_id": self.build_id,
            "tool": self.tool,
            "filename": self.filename,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "ttl_seconds": self.ttl_seconds,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ArtifactMeta:
        return cls(**data)


class ArtifactStore:
    """Filesystem-backed artifact store with automatic TTL expiry.

    Artifacts are stored as:
        {artifact_dir}/{build_id}.bin   — the binary artifact
        {artifact_dir}/{build_id}.json  — metadata sidecar
    """

    def __init__(self, artifact_dir: Path | None = None, ttl_seconds: int | None = None):
        self._dir = artifact_dir or settings.artifact_dir
        self._ttl = ttl_seconds or settings.artifact_ttl_seconds

    def ensure_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)

    async def store(
        self,
        build_id: str,
        artifact: bytes,
        tool: str,
        filename: str,
        sha256: str,
    ) -> ArtifactMeta:
        """Store an artifact and its metadata."""
        self.ensure_dir()

        meta = ArtifactMeta(
            build_id=build_id,
            tool=tool,
            filename=filename,
            sha256=sha256,
            size_bytes=len(artifact),
            created_at=time.time(),
            ttl_seconds=self._ttl,
        )

        artifact_path = self._dir / f"{build_id}.bin"
        meta_path = self._dir / f"{build_id}.json"

        async with aiofiles.open(artifact_path, "wb") as f:
            await f.write(artifact)

        async with aiofiles.open(meta_path, "w") as f:
            await f.write(json.dumps(meta.to_dict(), indent=2))

        logger.info(
            "Stored artifact %s (%d bytes, TTL %ds)",
            build_id,
            len(artifact),
            self._ttl,
        )
        return meta

    async def retrieve(self, build_id: str) -> tuple[bytes, ArtifactMeta]:
        """Retrieve an artifact by build ID.

        Raises:
            ArtifactNotFoundError: If the artifact doesn't exist.
            ArtifactExpiredError: If the artifact has exceeded its TTL.
        """
        meta_path = self._dir / f"{build_id}.json"
        artifact_path = self._dir / f"{build_id}.bin"

        if not meta_path.exists() or not artifact_path.exists():
            raise ArtifactNotFoundError(build_id)

        async with aiofiles.open(meta_path, "r") as f:
            meta = ArtifactMeta.from_dict(json.loads(await f.read()))

        if meta.is_expired:
            await self._delete(build_id)
            raise ArtifactExpiredError(build_id)

        async with aiofiles.open(artifact_path, "rb") as f:
            artifact = await f.read()

        return artifact, meta

    async def cleanup_expired(self) -> int:
        """Delete all expired artifacts. Returns count of deleted items."""
        if not self._dir.exists():
            return 0

        deleted = 0
        for meta_path in self._dir.glob("*.json"):
            try:
                async with aiofiles.open(meta_path, "r") as f:
                    meta = ArtifactMeta.from_dict(json.loads(await f.read()))
                if meta.is_expired:
                    await self._delete(meta.build_id)
                    deleted += 1
            except Exception:
                logger.exception("Error cleaning up %s", meta_path)

        if deleted:
            logger.info("Cleaned up %d expired artifacts", deleted)
        return deleted

    async def _delete(self, build_id: str) -> None:
        artifact_path = self._dir / f"{build_id}.bin"
        meta_path = self._dir / f"{build_id}.json"
        artifact_path.unlink(missing_ok=True)
        meta_path.unlink(missing_ok=True)


# Global store instance
artifact_store = ArtifactStore()
