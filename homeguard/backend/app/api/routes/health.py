"""Liveness and the active scope policy."""

from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.config import Settings, get_settings
from app.database import check_database
from app.domain.policy import RFC1918_NETWORKS
from app.schemas import HealthResponse, ScopePolicy

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(settings: Annotated[Settings, Depends(get_settings)]):
    database_ok = check_database()
    body = HealthResponse(
        status="ok" if database_ok else "degraded",
        service=settings.app_name,
        version=settings.version,
        database="ok" if database_ok else "error",
        api_host=settings.api_host,
        api_port=settings.api_port,
        scope_policy=ScopePolicy(
            address_family="ipv4",
            allowed_ranges=[str(network) for network in RFC1918_NETWORKS],
            max_scope=f"/{settings.largest_prefix_length}",
            default_scope=f"/{settings.default_prefix_length}",
        ),
    )
    if database_ok:
        return body
    return JSONResponse(status_code=503, content=body.model_dump())
