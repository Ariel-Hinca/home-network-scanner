"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.config import get_settings
from app.database import init_db
from app.workers.scan_worker import start_worker, stop_worker


def create_app() -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        init_db(settings)
        start_worker()
        yield
        stop_worker()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        summary="Local defensive home-network scanner, phase 0 skeleton.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["Content-Type", settings.local_request_header],
    )
    app.include_router(api_router, prefix="/api")
    return app


app = create_app()
