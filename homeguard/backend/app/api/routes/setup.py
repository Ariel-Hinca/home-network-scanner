"""Operator setup and local session cookies."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.deps import get_db, optional_session, require_local_request
from app.config import Settings, get_settings
from app.domain.passwords import hash_passphrase, verify_passphrase
from app.models import AppSettings, AuditEvent, SessionToken, utcnow
from app.schemas import PassphraseBody, SetupStatus

router = APIRouter(prefix="/setup", tags=["setup"])
session_router = APIRouter(prefix="/session", tags=["session"])


def _settings_row(db: Session) -> AppSettings | None:
    return db.get(AppSettings, 1)


def _issue_session(response: Response, db: Session, settings: Settings) -> None:
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours)
    db.add(SessionToken(token_hash=digest, created_at=utcnow(), expires_at=expires))
    db.commit()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        samesite="strict",
        secure=settings.cookie_secure,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
    )


@router.get("", response_model=SetupStatus)
def setup_status(
    db: Annotated[Session, Depends(get_db)],
    session: Annotated[SessionToken | None, Depends(optional_session)],
) -> SetupStatus:
    row = _settings_row(db)
    return SetupStatus(
        setup_completed=bool(row and row.passphrase_hash),
        authenticated=session is not None,
    )


@router.post("", response_model=SetupStatus, status_code=201)
def complete_setup(
    body: PassphraseBody,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_local_request)],
) -> SetupStatus:
    row = _settings_row(db)
    if row and row.passphrase_hash:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "setup_complete",
                "message": "A passphrase is already stored on this machine.",
            },
        )
    if row is None:
        row = AppSettings(id=1)
        db.add(row)
    row.passphrase_hash = hash_passphrase(body.passphrase)
    row.setup_completed_at = utcnow()
    db.add(AuditEvent(action="setup_completed", subject="local-operator", detail="Passphrase hash stored"))
    db.commit()
    _issue_session(response, db, settings)
    return SetupStatus(setup_completed=True, authenticated=True)


@session_router.post("", response_model=SetupStatus)
def start_session(
    body: PassphraseBody,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_local_request)],
) -> SetupStatus:
    row = _settings_row(db)
    if row is None or not row.passphrase_hash:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "setup_required",
                "message": "Create a passphrase on the setup page first.",
            },
        )
    if not verify_passphrase(body.passphrase, row.passphrase_hash):
        raise HTTPException(
            status_code=401,
            detail={"code": "bad_passphrase", "message": "The passphrase does not match."},
        )
    db.add(AuditEvent(action="session_started", subject="local-operator", detail="Local session started"))
    db.commit()
    _issue_session(response, db, settings)
    return SetupStatus(setup_completed=True, authenticated=True)


@session_router.delete("", status_code=204)
def end_session(
    response: Response,
    settings: Annotated[Settings, Depends(get_settings)],
    _: Annotated[None, Depends(require_local_request)],
) -> None:
    response.delete_cookie(settings.session_cookie_name, path="/")
