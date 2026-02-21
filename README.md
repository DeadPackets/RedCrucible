# RedCrucible

On-demand offensive .NET assembly obfuscation API for red teamers. Produces freshly compiled, polymorphically unique artifacts on every request — achieving **0 detections against 11,644 YARA rules**.

## Overview

RedCrucible takes pre-compiled .NET offensive tools (Rubeus, SharpKatz, Seatbelt, etc.) and runs them through a configurable pipeline of obfuscation stages, producing unique output on every build. The pipeline is exposed via a REST API.

**Pipeline stages:**

| Stage | Input | Output | Description |
|---|---|---|---|
| `obfuscar` | .NET Assembly | .NET Assembly | IL-level obfuscation (renaming, string encryption) via [Obfuscar](https://www.obfuscar.com/) |
| `dnlib_patcher` | .NET Assembly | .NET Assembly | GUID randomization + IL mutation via custom [dnlib](https://github.com/0xd4d/dnlib) patcher |
| `donut` | .NET Assembly | Shellcode | Converts .NET assembly to position-independent shellcode via [Donut](https://github.com/TheWover/donut) |
| `polymorphic_loader` | Shellcode | Shellcode | Wraps shellcode in a polymorphic x86_64 stub with rolling XOR encryption, register rotation, instruction substitution, dead code insertion, block reordering, and optional SysWhispers3-style indirect syscalls |

Each build produces structurally unique machine code — different registers, different instructions, different layout, different encryption keys.

## Requirements

- **Python 3.12+**
- **.NET 8 SDK** (for Obfuscar and AssemblyPatcher)
- **x86_64 Linux** (strongly recommended — QEMU emulation on ARM64 causes .NET JIT crashes)
- **donut** CLI (built from source during Docker build, or install manually)

## Quick Start

### Docker (Recommended)

```bash
# Pre-build .NET components (one-time)
dotnet publish tools/AssemblyPatcher/AssemblyPatcher.csproj \
    -c Release -o tools/AssemblyPatcher/publish --self-contained false

dotnet tool install --global Obfuscar.GlobalTool
# Copy DLLs: ~/.dotnet/tools/.store/obfuscar.globaltool/<version>/.../tools/net8.0/any/* -> tools/obfuscar/

# Build and run
docker build -t redcrucible:latest .
docker run -d -p 8000:8000 -v ./cache/assemblies:/app/cache/assemblies redcrucible:latest
```

### Local Development

```bash
# Install Python dependencies
uv sync --dev

# Install .NET tooling
dotnet tool install --global Obfuscar.GlobalTool
dotnet publish tools/AssemblyPatcher/AssemblyPatcher.csproj \
    -c Release -o tools/AssemblyPatcher/publish --self-contained false

# Build donut from source
git clone --depth 1 https://github.com/TheWover/donut.git /tmp/donut
cd /tmp/donut && make && sudo cp donut /usr/local/bin/

# Run the server
uv run uvicorn redcrucible.main:app --host 0.0.0.0 --port 8000
```

## API

### Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/tools` | List available tools |
| `GET` | `/api/v1/tools/{name}` | Get tool details (includes cache status) |
| `GET` | `/api/v1/tools/stages/available` | List available pipeline stages |
| `POST` | `/api/v1/build` | Build an obfuscated artifact |
| `GET` | `/api/v1/artifacts/{build_id}` | Download build artifact |

### Build Request

```bash
curl -X POST http://localhost:8000/api/v1/build \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "sharpkatz",
    "output_format": "shellcode",
    "architecture": "x64",
    "stages": [
      {"name": "obfuscar", "options": {"rename": true, "encrypt_strings": true}},
      {"name": "dnlib_patcher", "options": {"randomize_guids": true, "mutate_il": true}},
      {"name": "donut", "options": {"arch": "x64", "bypass": "continue", "entropy": 3}},
      {"name": "polymorphic_loader", "options": {
        "encryption": "aes", "syscalls": true, "junk_density": 3
      }}
    ]
  }'
```

Response:
```json
{
  "build_id": "abc123",
  "status": "completed",
  "download_url": "/api/v1/artifacts/abc123",
  "stages": ["obfuscar", "dnlib_patcher", "donut", "polymorphic_loader"]
}
```

Then download: `curl -O http://localhost:8000/api/v1/artifacts/abc123`

### Stage Options

**obfuscar:**
- `rename` (bool): Rename types/methods/fields
- `encrypt_strings` (bool): Encrypt string literals

**dnlib_patcher:**
- `randomize_guids` (bool): Replace all GUIDs with random values
- `mutate_il` (bool): Apply IL-level mutations (NOP insertion, branch inversion)

**donut:**
- `arch` ("x86" | "x64" | "x86+amd64"): Target architecture
- `bypass` ("none" | "abort" | "continue"): AMSI/WLDP bypass mode
- `entropy` (1-3): Encryption level (3 = full)

**polymorphic_loader:**
- `encryption` ("xor" | "aes"): Encryption mode (16-byte vs 32-byte rolling XOR key)
- `syscalls` (bool): Enable SysWhispers3-style indirect syscalls for memory allocation
- `junk_density` (1-5): Dead code insertion density

## Assembly Cache

Tools require pre-compiled base assemblies in `cache/assemblies/`. Structure matches `tools.yml`:

```
cache/assemblies/
  rubeus/Rubeus.exe
  sharpkatz/SharpKatz.exe
  seatbelt/Seatbelt.exe
  sharphound/SharpHound.exe
  certify/Certify.exe
```

Compile from source or obtain pre-built binaries and place them in the cache directory.

## YARA Verification

```bash
# Download YARA Forge rules
mkdir -p verify/rules/packages/full
wget -O verify/rules/packages/full/yara-rules-full.yar \
  "https://yaraify-api.abuse.ch/download/yaraify-rules.zip"
# (extract the full ruleset)

# Scan original vs obfuscated
uv run python verify/scan.py cache/assemblies/sharpkatz/SharpKatz.exe /tmp/obfuscated.bin
```

## Testing

```bash
# Unit tests (no external dependencies needed)
uv run pytest tests/ -v

# Integration tests against running container
uv run pytest tests/test_container_api.py -v
```

## Project Structure

```
redcrucible/
  api/              # FastAPI routes
  models/           # Pydantic request/response models
  pipeline/         # Stage registry, engine, context
  stages/           # Pipeline stage implementations
    _polymorph/     # Polymorphic shellcode engine
      register_allocator.py   # Random x86_64 register assignment
      instruction_subs.py     # Equivalent instruction substitutions
      dead_code.py            # Semantically neutral junk instructions
      block_reorder.py        # Code block shuffling with jmp linking
      encryption.py           # Rolling XOR payload encryption
      decryption_stub.py      # Polymorphic decryption loop generator
      syscall_stub.py         # SysWhispers3 indirect syscall generator
      engine.py               # Orchestrator
    obfuscar.py
    dnlib_patcher.py
    donut.py
    polymorphic_loader.py
  storage/          # Artifact storage with TTL
  tools/            # Tool registry and manifest loader
tools/
  AssemblyPatcher/  # .NET dnlib-based assembly patcher (C#)
  obfuscar/         # Pre-built Obfuscar net8.0 DLLs
verify/
  scan.py           # YARA-X scanner
  rules/            # YARA Forge rules (gitignored)
tests/              # pytest suite
```

## License

MIT
