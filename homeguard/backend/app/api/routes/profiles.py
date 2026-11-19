"""Built-in scan profiles. Phase 1 exposes discovery only."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_session
from app.models import ScanProfile
from app.schemas import ProfileOut

router = APIRouter(prefix="/profiles", tags=["profiles"])


@router.get("", response_model=list[ProfileOut])
def list_profiles(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[object, Depends(require_session)],
) -> list[ProfileOut]:
    rows = db.query(ScanProfile).order_by(ScanProfile.id.asc()).all()
    return [ProfileOut(key=row.key, name=row.name, port_set=row.port_set) for row in rows]
