from fastapi import APIRouter
from fastapi.responses import Response

from redcrucible.storage import artifact_store

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


CONTENT_TYPE_MAP = {
    ".exe": "application/vnd.microsoft.portable-executable",
    ".dll": "application/vnd.microsoft.portable-executable",
    ".bin": "application/octet-stream",
    ".shellcode": "application/octet-stream",
    ".ps1": "text/plain",
}


@router.get("/{build_id}")
async def download_artifact(build_id: str) -> Response:
    """Download a built artifact by its build ID.

    Raises 404 if the artifact doesn't exist or has expired.
    """
    artifact_bytes, meta = await artifact_store.retrieve(build_id)

    suffix = "." + meta.filename.rsplit(".", 1)[-1] if "." in meta.filename else ".bin"
    content_type = CONTENT_TYPE_MAP.get(suffix, "application/octet-stream")

    return Response(
        content=artifact_bytes,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{meta.filename}"',
            "X-Artifact-SHA256": meta.sha256,
            "X-Artifact-Size": str(meta.size_bytes),
        },
    )
