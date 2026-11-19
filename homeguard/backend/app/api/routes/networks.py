"""Scope validation and saved private networks."""

from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_local_request, require_session
from app.config import Settings, get_settings
from app.domain.interfaces import list_scan_interfaces
from app.domain.policy import ScopeRejected, validate_cidr
from app.models import Asset, AuditEvent, HostObservation, Network, Scan, Service, utcnow
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

    existing = db.query(Network).filter(Network.cidr == validated.cidr).one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "network_already_saved",
                "message": "This home network is already saved. You do not need to add it again.",
            },
        )

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


@router.post("/networks/{network_id}/confirm", response_model=NetworkOut)
def confirm_network(
    network_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_local_request)],
    __: Annotated[object, Depends(require_session)],
) -> NetworkOut:
    row = db.get(Network, network_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "network_not_found", "message": "That saved network was not found."},
        )
    if row.ownership_confirmed_at is None:
        row.ownership_confirmed_at = utcnow()
        db.add(
            AuditEvent(
                action="network_confirmed",
                subject=row.cidr,
                detail="Operator confirmed this network may be discovered.",
                network_id=row.id,
            )
        )
        db.commit()
        db.refresh(row)
    return _to_out(row)


@router.delete("/networks/{network_id}", status_code=204)
def delete_network(
    network_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_local_request)],
    __: Annotated[object, Depends(require_session)],
) -> None:
    row = db.get(Network, network_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "network_not_found", "message": "That saved network was not found."},
        )
    active = (
        db.query(Scan.id)
        .filter(Scan.network_id == row.id, Scan.status.in_(("queued", "running")))
        .first()
    )
    if active is not None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "scan_in_progress",
                "message": "A search is still running on this network. Stop it before removing the network.",
            },
        )
    scan_ids = [scan_id for (scan_id,) in db.query(Scan.id).filter(Scan.network_id == row.id).all()]
    xml_paths = [
        path
        for (path,) in db.query(Scan.xml_path).filter(Scan.network_id == row.id).all()
        if path
    ]
    if scan_ids:
        observation_ids = [
            observation_id
            for (observation_id,) in db.query(HostObservation.id).filter(HostObservation.scan_id.in_(scan_ids)).all()
        ]
        if observation_ids:
            db.query(Service).filter(Service.observation_id.in_(observation_ids)).delete(synchronize_session=False)
        db.query(HostObservation).filter(HostObservation.scan_id.in_(scan_ids)).delete(synchronize_session=False)
        db.query(Scan).filter(Scan.id.in_(scan_ids)).delete(synchronize_session=False)
    db.query(Asset).filter(Asset.network_id == row.id).delete(synchronize_session=False)
    db.query(AuditEvent).filter(AuditEvent.network_id == row.id).delete(synchronize_session=False)
    cidr = row.cidr
    db.delete(row)
    db.add(
        AuditEvent(
            action="network_removed",
            subject=cidr,
            detail="The saved home network and its device list were removed.",
        )
    )
    db.commit()
    for raw_path in xml_paths:
        Path(raw_path).unlink(missing_ok=True)


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
