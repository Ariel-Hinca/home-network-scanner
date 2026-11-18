"""API router. Mounted at /api."""

from fastapi import APIRouter

from app.api.routes import audit, health, networks, scans, setup

api_router = APIRouter()
api_router.include_router(health.router)
api_router.include_router(setup.router)
api_router.include_router(setup.session_router)
api_router.include_router(networks.router)
api_router.include_router(scans.router)
api_router.include_router(audit.router)
