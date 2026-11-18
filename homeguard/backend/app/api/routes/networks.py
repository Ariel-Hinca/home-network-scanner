"""Scope validation and saved private networks."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_local_request, require_session
from app.config import Settings, get_settings
from app.domain.interfaces import list_scan_interfaces
from app.domain.policy import ScopeRejected, validate_cidr
from app.models import AuditEvent, Network, utcnow
from app.schemas import CidrBody, InterfaceOut, NetworkCreate, NetworkOut, ValidatedCidr

router = APIRouter(tags=["networks"])


def _scope_error(exc: ScopeRejected) -> HTTPException:
    return HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message})


def _validated_payload(cidr: str, settings: Settings) -> ValidatedCidr:
    scope = validate_cidr(cidr, largest_prefix_length=settings.largest_prefix_length)
    return ValidatedCidr(
        cidr=scope.cidr,
        prefix_length=scope.prefix_length,
        num_addresses=scope.num_addresses,
        private=True,
        within_max_scope=True,
        host_bits_normalized=scope.host_bits_normalized,
        max_scope=f"/{settings.largest_prefix_length}",
        default_scope=f"/{settings.default_prefix_length}",
    )


@router.get("/interfaces", response_model=list[InterfaceOut])
def interfaces(settings: Annotated[Settings, Depends(get_settings)]) -> list[InterfaceOut]:
    rows = list_scan_interfaces(
        largest_prefix_length=settings.largest_prefix_length,
        default_prefix_length=settings.default_prefix_length,
    )
    return [InterfaceOut.model_validate(row, from_attributes=True) for row in rows]


@router.post("/networks/validate", response_model=ValidatedCidr)
def validate_network(
    body: CidrBody,
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_local_request)],
) -> ValidatedCidr:
    try:
        return _validated_payload(body.cidr, settings)
    except ScopeRejected as exc:
        raise _scope_error(exc) from exc


@router.get("/networks", response_model=list[NetworkOut])
def list_networks(db: Annotated[Session, Depends(get_db)]) -> list[NetworkOut]:
    rows = db.query(Network).order_by(Network.id.desc()).all()
    return [_to_out(row) for row in rows]


@router.post("/networks", response_model=NetworkOut, status_code=201)
def create_network(
    body: NetworkCreate,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_local_request)],
    __: Annotated[object, Depends(require_session)],
) -> NetworkOut:
    try:
        validated = _validated_payload(body.cidr, settings)
    except ScopeRejected as exc:
        raise _scope_error(exc) from exc

    row = Network(
        name=body.name.strip(),
        cidr=validated.cidr,
        prefix_length=validated.prefix_length,
        interface_name=body.interface_name,
        ownership_confirmed_at=None,
        created_at=utcnow(),
    )
    db.add(row)
    db.flush()
    db.add(
        AuditEvent(
            action="network_saved",
            subject=validated.cidr,
            detail="Saved as an unconfirmed scope. Scanning starts in a later phase.",
            network_id=row.id,
        )
    )
    db.commit()
    db.refresh(row)
    return _to_out(row)


def _to_out(row: Network) -> NetworkOut:
    return NetworkOut(
        id=row.id,
        name=row.name,
        cidr=row.cidr,
        prefix_length=row.prefix_length,
        interface_name=row.interface_name,
        ownership_confirmed=row.ownership_confirmed_at is not None,
        created_at=row.created_at,
    )
