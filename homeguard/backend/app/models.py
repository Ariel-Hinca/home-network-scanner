"""SQLAlchemy models for the phase 0 skeleton.

Scans are represented only as a reserved table name in later phases. This
phase stores scope, the local operator passphrase, and sessions.
"""

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    passphrase_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    setup_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SessionToken(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Network(Base):
    __tablename__ = "networks"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    cidr: Mapped[str] = mapped_column(String(64))
    prefix_length: Mapped[int]
    interface_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ownership_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    action: Mapped[str] = mapped_column(String(64))
    subject: Mapped[str] = mapped_column(String(160), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    network_id: Mapped[int | None] = mapped_column(ForeignKey("networks.id"), nullable=True)
