"""Integration tests against the live RedCrucible container API.

Run with: pytest tests/test_container_api.py -v
Requires: Container running on localhost:8000 with SharpKatz cached.
"""

import hashlib
import time

import httpx
import pytest

BASE_URL = "http://localhost:8000"


@pytest.fixture(scope="module")
def client():
    with httpx.Client(base_url=BASE_URL, timeout=300) as c:
        yield c


# ---------- Health ----------


def test_health(client: httpx.Client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["tools_loaded"] == 5
    assert data["stages_registered"] == 4


# ---------- Tools ----------


def test_list_tools(client: httpx.Client):
    resp = client.get("/api/v1/tools")
    assert resp.status_code == 200
    tools = resp.json()
    assert len(tools) == 5
    names = {t["name"] for t in tools}
    assert names == {"rubeus", "seatbelt", "sharpkatz", "sharphound", "certify"}


def test_get_tool_detail(client: httpx.Client):
    resp = client.get("/api/v1/tools/sharpkatz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "sharpkatz"
    assert data["display_name"] == "SharpKatz"
    assert data["cached"] is True


def test_get_unknown_tool(client: httpx.Client):
    resp = client.get("/api/v1/tools/nonexistent")
    assert resp.status_code == 404


# ---------- Stages ----------


def test_list_stages(client: httpx.Client):
    resp = client.get("/api/v1/tools/stages/available")
    assert resp.status_code == 200
    stages = resp.json()
    names = {s["name"] for s in stages}
    assert {"obfuscar", "dnlib_patcher", "donut", "polymorphic_loader"} <= names


# ---------- Build (no assembly cached) ----------


def test_build_uncached_tool_fails_gracefully(client: httpx.Client):
    resp = client.post("/api/v1/build", json={
        "tool": "rubeus",
        "output_format": "exe",
        "architecture": "x64",
        "stages": [],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "failed"
    assert "not cached" in data["error"]


def test_build_unknown_tool(client: httpx.Client):
    resp = client.post("/api/v1/build", json={
        "tool": "nonexistent",
        "output_format": "exe",
        "architecture": "x64",
    })
    assert resp.status_code == 404


# ---------- Build: Obfuscar ----------


def test_build_obfuscar(client: httpx.Client):
    resp = client.post("/api/v1/build", json={
        "tool": "sharpkatz",
        "output_format": "exe",
        "architecture": "x64",
        "stages": [
            {"name": "obfuscar", "options": {"rename": True, "encrypt_strings": True}},
        ],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed", f"Build failed: {data.get('error')}"
    assert data["download_url"] is not None

    # Download artifact
    artifact_resp = client.get(data["download_url"])
    assert artifact_resp.status_code == 200
    artifact = artifact_resp.content
    assert len(artifact) > 0
    assert artifact[:2] == b"MZ", "Output should be a PE file"


# ---------- Build: Obfuscar + dnlib_patcher ----------


def test_build_obfuscar_dnlib(client: httpx.Client):
    resp = client.post("/api/v1/build", json={
        "tool": "sharpkatz",
        "output_format": "exe",
        "architecture": "x64",
        "stages": [
            {"name": "obfuscar", "options": {"rename": True, "encrypt_strings": True}},
            {"name": "dnlib_patcher", "options": {"randomize_guids": True, "mutate_il": True}},
        ],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed", f"Build failed: {data.get('error')}"
    assert data["download_url"] is not None

    artifact_resp = client.get(data["download_url"])
    assert artifact_resp.status_code == 200
    artifact = artifact_resp.content
    assert artifact[:2] == b"MZ"


# ---------- Build: Full pipeline to shellcode ----------


def test_build_full_pipeline_shellcode(client: httpx.Client):
    resp = client.post("/api/v1/build", json={
        "tool": "sharpkatz",
        "output_format": "shellcode",
        "architecture": "x64",
        "stages": [
            {"name": "obfuscar", "options": {"rename": True, "encrypt_strings": True}},
            {"name": "dnlib_patcher", "options": {"randomize_guids": True, "mutate_il": True}},
            {"name": "donut", "options": {"arch": "x64", "bypass": "continue", "entropy": 3}},
        ],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed", f"Build failed: {data.get('error')}"

    artifact_resp = client.get(data["download_url"])
    assert artifact_resp.status_code == 200
    shellcode = artifact_resp.content
    assert len(shellcode) > 1000, "Shellcode should be substantial"


# ---------- Build: Full pipeline + polymorphic loader ----------


def test_build_full_pipeline_polymorphic(client: httpx.Client):
    resp = client.post("/api/v1/build", json={
        "tool": "sharpkatz",
        "output_format": "shellcode",
        "architecture": "x64",
        "stages": [
            {"name": "obfuscar", "options": {"rename": True, "encrypt_strings": True}},
            {"name": "dnlib_patcher", "options": {"randomize_guids": True, "mutate_il": True}},
            {"name": "donut", "options": {"arch": "x64", "bypass": "continue", "entropy": 3}},
            {"name": "polymorphic_loader", "options": {
                "encryption": "aes", "syscalls": True, "junk_density": 3,
            }},
        ],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "completed", f"Build failed: {data.get('error')}"

    artifact_resp = client.get(data["download_url"])
    assert artifact_resp.status_code == 200
    shellcode = artifact_resp.content
    assert len(shellcode) > 5000, "Polymorphic shellcode should be large"


# ---------- Uniqueness: two builds produce different output ----------


def test_builds_produce_unique_output(client: httpx.Client):
    hashes = []
    for _ in range(2):
        resp = client.post("/api/v1/build", json={
            "tool": "sharpkatz",
            "output_format": "shellcode",
            "architecture": "x64",
            "stages": [
                {"name": "obfuscar", "options": {"rename": True, "encrypt_strings": True}},
                {"name": "dnlib_patcher", "options": {"randomize_guids": True, "mutate_il": True}},
                {"name": "donut", "options": {"arch": "x64", "entropy": 3}},
                {"name": "polymorphic_loader", "options": {
                    "encryption": "xor", "syscalls": False, "junk_density": 2,
                }},
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed", f"Build failed: {data.get('error')}"
        artifact_resp = client.get(data["download_url"])
        hashes.append(hashlib.sha256(artifact_resp.content).hexdigest())

    assert hashes[0] != hashes[1], "Each build should produce unique output"


# ---------- OpenAPI docs ----------


def test_openapi_docs(client: httpx.Client):
    resp = client.get("/docs")
    assert resp.status_code == 200
    assert "swagger" in resp.text.lower() or "redcrucible" in resp.text.lower()
