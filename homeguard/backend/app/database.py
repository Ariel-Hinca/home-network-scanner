"""SQLite engine and session factory. The worker is the only writer in later phases."""

from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import BACKEND_ROOT, Settings
from app.models import Base

SessionLocal: sessionmaker[Session] | None = None
engine: Engine | None = None


def resolve_database_url(url: str) -> str:
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        raise ValueError("Phase 0 uses a SQLite database URL starting with sqlite:///")
    raw = url[len(prefix) :]
    if raw == ":memory:":
        return "sqlite:///:memory:"
    path = Path(raw)
    if not path.is_absolute():
        path = (BACKEND_ROOT / path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{path.as_posix()}"


def init_db(settings: Settings) -> Engine:
    global engine, SessionLocal
    database_url = resolve_database_url(settings.database_url)
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False},
    )
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:  # type: ignore[no-untyped-def]
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    return engine


def check_database() -> bool:
    if engine is None:
        return False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_session_factory() -> sessionmaker[Session]:
    if SessionLocal is None:
        raise RuntimeError("Database is not initialized")
    return SessionLocal
