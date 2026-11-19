"""One background pass at a time. The API process starts and stops it."""

from __future__ import annotations

import threading
from pathlib import Path

from sqlalchemy.orm import Session

from app.adapters.identity import identify_hosts
from app.adapters.nmap.parser import parse_discovery_xml, parse_port_scan_xml
from app.adapters.nmap.runner import NmapFailed, find_nmap, run_discovery, run_port_scan
from app.config import BACKEND_ROOT, get_settings
from app.database import get_session_factory
from app.models import Asset, AuditEvent, HostObservation, Network, Scan, ScanProfile, Service, utcnow

ACTIVE_STATUSES = ("queued", "running")
_stop = threading.Event()
_thread: threading.Thread | None = None
_events: dict[int, threading.Event] = {}
_events_lock = threading.Lock()


def start_worker() -> None:
    global _thread
    stop_worker()
    with _events_lock:
        _events.clear()
    _stop.clear()
    _recover_interrupted_scans()
    _thread = threading.Thread(target=_loop, name="homeguard-scan-worker", daemon=True)
    _thread.start()


def stop_worker() -> None:
    _stop.set()
    with _events_lock:
        for event in _events.values():
            event.set()
    thread = _thread
    if thread is not None and thread is not threading.current_thread():
        thread.join(timeout=2)


def cancel_event_for(scan_id: int) -> threading.Event:
    with _events_lock:
        event = _events.get(scan_id)
        if event is None:
            event = threading.Event()
            _events[scan_id] = event
        return event


def request_cancel(scan_id: int) -> None:
    cancel_event_for(scan_id).set()


def active_scan_exists(db: Session) -> bool:
    return (
        db.query(Scan.id)
        .filter(Scan.status.in_(ACTIVE_STATUSES))
        .first()
        is not None
    )


def _loop() -> None:
    while not _stop.is_set():
        scan_id = _claim_next_scan()
        if scan_id is None:
            _stop.wait(0.2)
            continue
        try:
            _execute(scan_id)
        except Exception as exc:  # noqa: BLE001 — the worker must record the failure
            _mark_failed(scan_id, str(exc)[:500] or "Discovery failed.")


def _recover_interrupted_scans() -> None:
    db = get_session_factory()()
    try:
        rows = db.query(Scan).filter(Scan.status == "running").all()
        for row in rows:
            row.status = "failed"
            row.error = "The app restarted while this discovery was running."
            row.finished_at = utcnow()
        if rows:
            db.commit()
    finally:
        db.close()


def _claim_next_scan() -> int | None:
    db = get_session_factory()()
    try:
        running = db.query(Scan.id).filter(Scan.status == "running").first()
        if running is not None:
            return None
        row = (
            db.query(Scan)
            .filter(Scan.status == "queued")
            .order_by(Scan.id.asc())
            .first()
        )
        if row is None:
            return None
        if cancel_event_for(row.id).is_set():
            row.status = "cancelled"
            row.finished_at = utcnow()
            db.commit()
            return None
        row.status = "running"
        row.started_at = utcnow()
        db.commit()
        return row.id
    finally:
        db.close()


def _execute(scan_id: int) -> None:
    settings = get_settings()
    db = get_session_factory()()
    try:
        scan = db.get(Scan, scan_id)
        network = db.get(Network, scan.network_id) if scan is not None else None
        if scan is None or network is None:
            return
        if cancel_event_for(scan_id).is_set():
            _finish(db, scan, "cancelled", "")
            return
        profile = db.get(ScanProfile, scan.profile_id)
        profile_key = profile.key if profile is not None else "discovery"
        nmap_bin = find_nmap(settings.nmap_path)
        if nmap_bin is None:
            _finish(db, scan, "failed", "Nmap is not installed, or HomeGuard cannot find it.")
            return
        targets = _target_addresses(db, scan) if profile_key == "common_tcp" else []
        if profile_key == "common_tcp" and not targets:
            _finish(db, scan, "failed", "No devices were saved from the earlier search.")
            return
        xml_path = _xml_path(scan_id)
        scan.xml_path = str(xml_path)
        db.commit()
        cidr = network.cidr
        timeout = settings.scan_timeout_seconds
    finally:
        db.close()

    try:
        if profile_key == "common_tcp":
            outcome = run_port_scan(
                nmap_bin,
                targets,
                xml_path,
                cancel_event_for(scan_id),
                timeout,
            )
        else:
            outcome = run_discovery(
                nmap_bin,
                cidr,
                xml_path,
                cancel_event_for(scan_id),
                timeout,
            )
    except NmapFailed as exc:
        _mark_failed(scan_id, exc.message)
        return

    db = get_session_factory()()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        if outcome == "cancelled" or cancel_event_for(scan_id).is_set():
            _finish(db, scan, "cancelled", "")
            return
        hosts = parse_port_scan_xml(xml_path) if profile_key == "common_tcp" else parse_discovery_xml(xml_path)
        hosts = identify_hosts(hosts, nmap_bin)
        _store_hosts(db, scan, hosts)
        scan.host_count = len(hosts)
        _finish(db, scan, "completed", "")
        detail = (
            f"Port check finished for {len(hosts)} device(s)."
            if profile_key == "common_tcp"
            else f"{len(hosts)} device(s) answered."
        )
        db.add(
            AuditEvent(
                action="scan_completed",
                subject=cidr,
                detail=detail,
                network_id=scan.network_id,
            )
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        _mark_failed(scan_id, str(exc))
    finally:
        db.close()


def _store_hosts(db: Session, scan: Scan, hosts) -> None:
    now = utcnow()
    for host in hosts:
        asset = (
            db.query(Asset)
            .filter(Asset.network_id == scan.network_id, Asset.ip == host.ip)
            .one_or_none()
        )
        if asset is None:
            asset = Asset(
                network_id=scan.network_id,
                ip=host.ip,
                hostname=host.hostname,
                mac=host.mac,
                vendor=host.vendor,
                first_seen=now,
                last_seen=now,
            )
            db.add(asset)
            db.flush()
        else:
            asset.last_seen = now
            if host.hostname:
                asset.hostname = host.hostname
            if host.mac:
                asset.mac = host.mac
            if host.vendor:
                asset.vendor = host.vendor
        observation = HostObservation(
            scan_id=scan.id,
            asset_id=asset.id,
            ip=host.ip,
            hostname=asset.hostname,
            mac=asset.mac,
            vendor=asset.vendor,
            state="up",
            seen_at=now,
        )
        db.add(observation)
        db.flush()
        for port in host.ports:
            db.add(
                Service(
                    observation_id=observation.id,
                    port=port.port,
                    protocol=port.protocol,
                    state=port.state,
                )
            )


def _target_addresses(db: Session, scan: Scan) -> list[str]:
    if scan.parent_scan_id is None:
        return []
    rows = (
        db.query(HostObservation.ip)
        .filter(HostObservation.scan_id == scan.parent_scan_id)
        .order_by(HostObservation.ip.asc())
        .all()
    )
    return [ip for (ip,) in rows]


def _finish(db: Session, scan: Scan, status: str, error: str) -> None:
    scan.status = status
    scan.error = error
    scan.finished_at = utcnow()
    db.commit()


def _mark_failed(scan_id: int, message: str) -> None:
    db = get_session_factory()()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status in {"completed", "cancelled"}:
            return
        scan.status = "failed"
        scan.error = message
        scan.finished_at = utcnow()
        db.commit()
    finally:
        db.close()


def _xml_path(scan_id: int) -> Path:
    directory = BACKEND_ROOT / "data" / "scans"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{scan_id}.xml"


def profile_by_key(db: Session, key: str) -> ScanProfile | None:
    return db.query(ScanProfile).filter(ScanProfile.key == key).one_or_none()

