##############################################################################
# RedCrucible — Multi-stage Dockerfile
#
# Runtime targets linux/amd64 so x86_64 tooling (donut, keystone) works
# natively. On ARM64 hosts this runs under QEMU emulation.
#
# .NET components (AssemblyPatcher, Obfuscar) are platform-independent IL
# and are pre-built on the host (see Makefile / CI). Only the donut CLI
# needs to be compiled as an x86_64 native binary.
#
# Pre-build steps (run before `docker build`):
#   1. dotnet publish tools/AssemblyPatcher/AssemblyPatcher.csproj \
#          -c Release -o tools/AssemblyPatcher/publish --self-contained false
#   2. Copy Obfuscar net8.0 DLLs to tools/obfuscar/ (from dotnet global tool store)
##############################################################################

# ---- Stage 1: Build donut CLI from source (x86_64) ----
FROM --platform=linux/amd64 debian:bookworm-slim AS donut-build

RUN apt-get update && apt-get install -y --no-install-recommends \
        git gcc make ca-certificates libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 https://github.com/TheWover/donut.git . \
    && make -j$(nproc) \
    && cp donut /usr/local/bin/donut


# ---- Stage 2: Runtime image (x86_64) ----
FROM --platform=linux/amd64 python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=false \
    PATH="/root/.dotnet:/root/.dotnet/tools:${PATH}"

WORKDIR /app

# .NET 8 runtime (platform-independent IL only — no SDK needed) + ICU
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libicu72 \
        curl \
    && curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel 8.0 --runtime dotnet --install-dir /root/.dotnet \
    && rm /tmp/dotnet-install.sh \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Pre-built Obfuscar (platform-independent .NET IL)
COPY tools/obfuscar/ /opt/obfuscar/
RUN printf '#!/bin/sh\nexec dotnet /opt/obfuscar/GlobalTools.dll "$@"\n' \
        > /usr/local/bin/obfuscar.console \
    && chmod +x /usr/local/bin/obfuscar.console

# Pre-built AssemblyPatcher (platform-independent .NET IL)
COPY tools/AssemblyPatcher/publish/ /opt/assembly-patcher/
RUN printf '#!/bin/sh\nexec dotnet /opt/assembly-patcher/AssemblyPatcher.dll "$@"\n' \
        > /usr/local/bin/assembly-patcher \
    && chmod +x /usr/local/bin/assembly-patcher

# Donut binary (x86_64 native)
COPY --from=donut-build /usr/local/bin/donut /usr/local/bin/donut

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Python dependencies (layer caching: deps before code)
COPY pyproject.toml ./
RUN uv sync --no-dev --no-install-project

# Application code
COPY redcrucible/ redcrucible/
COPY tools.yml ./
RUN uv sync --no-dev

# Runtime directories
RUN mkdir -p /app/artifacts /app/cache/assemblies

# Tests + verification tooling
COPY tests/ tests/
COPY verify/ verify/

ENV REDCRUCIBLE_ARTIFACT_DIR=/app/artifacts \
    REDCRUCIBLE_ASSEMBLY_CACHE_DIR=/app/cache/assemblies \
    REDCRUCIBLE_TOOLS_MANIFEST=/app/tools.yml

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "redcrucible.main:app", "--host", "0.0.0.0", "--port", "8000"]
