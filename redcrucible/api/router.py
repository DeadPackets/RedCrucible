from fastapi import APIRouter

from .routes import artifacts, build, health, tools

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(build.router)
api_router.include_router(tools.router)
api_router.include_router(artifacts.router)

# Health is mounted at root, not under /api/v1
health_router = health.router
