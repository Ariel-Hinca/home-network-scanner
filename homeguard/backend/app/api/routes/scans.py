"""Host discovery. One scan runs at a time, and only on a confirmed network."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_local_request, require_session
from app.config import Settings, get_settings
from app.domain.policy import ScopeRejected, assert_scan_size, validate_cidr
from app.models import AuditEvent, HostObservation, Network, Scan, utcnow
from app.schemas import HostOut, ScanCreate, ScanOut
from app.workers.scan_worker import active_scan_exists, cancel_event_for, profile_by_key, request_cancel

router = APIRouter(prefix="/scans", tags=["scans"])


def _to_out(row: Scan, profile_key: str) -> ScanOut:
    return ScanOut(
        id=row.id,
        network_id=row.network_id,
        profile=profile_key,
        status=row.status,
        error=row.error,
        host_count=row.host_count,
        created_at=row.created_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


def _profile_key(db: Session, row: Scan) -> str:
    from app.models import ScanProfile

    profile = db.get(ScanProfile, row.profile_id)
    return profile.key if profile is not None else ""


@router.get("", response_model=list[ScanOut])
def list_scans(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[object, Depends(require_session)],
) -> list[ScanOut]:
    rows = db.query(Scan).order_by(Scan.id.desc()).all()
    return [_to_out(row, _profile_key(db, row)) for row in rows]


@router.post("", response_model=ScanOut, status_code=201)
def start_scan(
    body: ScanCreate,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_local_request)],
    __: Annotated[object, Depends(require_session)],
) -> ScanOut:
    if body.profile != "discovery":
        raise HTTPException(
            status_code=400,
            detail={
                "code": "unknown_profile",
                "message": "Phase 1 can only run the discovery profile.",
            },
        )
    network = db.get(Network, body.network_id)
    if network is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "network_not_found", "message": "That saved network was not found."},
        )
    if network.ownership_confirmed_at is None:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ownership_required",
                "message": "Confirm that you are allowed to scan this network first.",
            },
        )
    try:
        validate_cidr(network.cidr, largest_prefix_length=settings.largest_prefix_length)
        assert_scan_size(network.prefix_length, scan_min_prefix_length=settings.scan_min_prefix_length)
    except ScopeRejected as exc:
        raise HTTPException(status_code=400, detail={"code": exc.code, "message": exc.message}) from exc

    if active_scan_exists(db):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "scan_in_progress",
                "message": "A discovery is already running. Wait for it to finish or cancel it.",
            },
        )
    profile = profile_by_key(db, "discovery")
    if profile is None:
        raise HTTPException(
            status_code=500,
            detail={"code": "profile_missing", "message": "The discovery profile is not installed."},
        )
    scan = Scan(
        network_id=network.id,
        profile_id=profile.id,
        status="queued",
        error="",
        host_count=0,
        created_at=utcnow(),
    )
    db.add(scan)
    db.flush()
    db.add(
        AuditEvent(
            action="scan_started",
            subject=network.cidr,
            detail="Discovery queued.",
            network_id=network.id,
        )
    )
    db.commit()
    db.refresh(scan)
    cancel_event_for(scan.id)
    return _to_out(scan, "discovery")


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[object, Depends(require_session)],
) -> ScanOut:
    row = db.get(Scan, scan_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "scan_not_found", "message": "That discovery was not found."},
        )
    return _to_out(row, _profile_key(db, row))


@router.post("/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_local_request)],
    __: Annotated[object, Depends(require_session)],
) -> ScanOut:
    row = db.get(Scan, scan_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "scan_not_found", "message": "That discovery was not found."},
        )
    if row.status == "queued":
        row.status = "cancelled"
        row.finished_at = utcnow()
        db.add(
            AuditEvent(
                action="scan_cancelled",
                subject=str(row.network_id),
                detail="Discovery cancelled before it started.",
                network_id=row.network_id,
            )
        )
        db.commit()
        db.refresh(row)
    if row.status == "running":
        request_cancel(row.id)
    else:
        request_cancel(row.id)
    return _to_out(row, _profile_key(db, row))


@router.get("/{scan_id}/hosts", response_model=list[HostOut])
def list_hosts(
    scan_id: int,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[object, Depends(require_session)],
) -> list[HostOut]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "scan_not_found", "message": "That discovery was not found."},
        )
    rows = (
        db.query(HostObservation)
        .filter(HostObservation.scan_id == scan.id)
        .order_by(HostObservation.ip.asc())
        .all()
    )
    return [HostOut(ip=row.ip, hostname=row.hostname, state=row.state) for row in rows]
