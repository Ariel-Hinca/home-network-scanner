"""Shared request dependencies."""

import hashlib
from datetime import timezone
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_session_factory
from app.models import SessionToken


def get_db():
    factory = get_session_factory()
    db = factory()
    try:
        yield db
    finally:
        db.close()


def require_local_request(
    settings: Annotated[Settings, Depends(get_settings)],
    x_homeguard_request: Annotated[str | None, Header()] = None,
) -> None:
    if x_homeguard_request != "1":
        raise HTTPException(
            status_code=403,
            detail={
                "code": "missing_local_header",
                "message": f"Mutating requests must include {settings.local_request_header}: 1.",
            },
        )


def _as_utc(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def optional_session(
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionToken | None:
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    row = db.query(SessionToken).filter(SessionToken.token_hash == digest).one_or_none()
    if row is None:
        return None
    from datetime import datetime

    if _as_utc(row.expires_at) <= datetime.now(timezone.utc):
        return None
    return row


def require_session(
    session: Annotated[SessionToken | None, Depends(optional_session)],
) -> SessionToken:
    if session is None:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "auth_required",
                "message": "Sign in from the setup page before saving a network.",
            },
        )
    return session
