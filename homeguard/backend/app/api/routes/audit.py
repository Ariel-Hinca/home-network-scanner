"""Recent local audit events. Passphrases are never written here."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_session
from app.models import AuditEvent
from app.schemas import AuditOut

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditOut])
def list_audit(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[object, Depends(require_session)],
) -> list[AuditEvent]:
    return db.query(AuditEvent).order_by(AuditEvent.id.desc()).limit(50).all()
