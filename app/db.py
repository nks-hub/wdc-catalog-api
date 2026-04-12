"""SQLAlchemy setup + ORM models for the catalog API.

Schema:
    apps         — one row per application (id = canonical name)
    releases     — versioned release per app
    downloads    — per-platform download URL for a release
    users        — admin users with bcrypt-hashed passwords
    config_sync  — per-device config snapshots

SQLite is the default backend (`catalog.db` under the state dir). Switch to
Postgres via `DATABASE_URL=postgresql+psycopg://...` when the install
outgrows a single file. The ORM layer and queries are DB-agnostic so the
migration is a one-line change.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from sqlalchemy import (
    JSON,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    Session,
    sessionmaker,
)


def _database_url() -> str:
    env = os.environ.get("DATABASE_URL")
    if env:
        return env
    state_dir = Path(
        os.environ.get("NKS_WDC_CATALOG_STATE_DIR")
        or (Path(__file__).parent.parent / "state")
    ).resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{state_dir / 'catalog.db'}"


_engine = create_engine(
    _database_url(),
    connect_args={"check_same_thread": False} if "sqlite" in _database_url() else {},
    echo=False,
    future=True,
)
_SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class App(Base):
    __tablename__ = "apps"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    category: Mapped[str] = mapped_column(String(32), default="other")
    description: Mapped[str] = mapped_column(String(2048), default="")
    homepage: Mapped[str | None] = mapped_column(String(512), nullable=True)
    license: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, onupdate=_utc_now)

    releases: Mapped[list["Release"]] = relationship(
        "Release",
        back_populates="app",
        cascade="all, delete-orphan",
        order_by="Release.version.desc()",
    )


class Release(Base):
    __tablename__ = "releases"
    __table_args__ = (UniqueConstraint("app_id", "version", name="uq_release_version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    app_id: Mapped[str] = mapped_column(ForeignKey("apps.id", ondelete="CASCADE"), index=True)
    version: Mapped[str] = mapped_column(String(64))
    major_minor: Mapped[str] = mapped_column(String(32), default="")
    channel: Mapped[str] = mapped_column(String(32), default="stable")
    released_at: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)

    app: Mapped[App] = relationship("App", back_populates="releases")
    downloads: Mapped[list["Download"]] = relationship(
        "Download",
        back_populates="release",
        cascade="all, delete-orphan",
        order_by="Download.os, Download.arch",
    )


class Download(Base):
    __tablename__ = "downloads"
    __table_args__ = (
        UniqueConstraint(
            "release_id", "os", "arch", "archive_type",
            name="uq_download_platform",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    release_id: Mapped[int] = mapped_column(
        ForeignKey("releases.id", ondelete="CASCADE"), index=True
    )
    url: Mapped[str] = mapped_column(String(1024))
    os: Mapped[str] = mapped_column(String(16), default="windows")
    arch: Mapped[str] = mapped_column(String(16), default="x64")
    archive_type: Mapped[str] = mapped_column(String(16), default="zip")
    source: Mapped[str] = mapped_column(String(64), default="unknown")
    headers: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    release: Mapped[Release] = relationship("Release", back_populates="downloads")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(128), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceConfig(Base):
    __tablename__ = "device_configs"

    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os: Mapped[str | None] = mapped_column(String(16), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(16), nullable=True)
    site_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, onupdate=_utc_now)
    payload: Mapped[dict] = mapped_column(JSON)


# ── Session helper ──────────────────────────────────────────────────────

def create_all() -> None:
    """Idempotent schema creation — run on app startup.

    Uses ``checkfirst=True`` (the SQLAlchemy default) so ``CREATE TABLE``
    is skipped when the table already exists. Wrapped in a catch-all
    because some SQLite builds or concurrent-startup races can still
    raise ``OperationalError: table X already exists`` even with
    checkfirst — treating it as benign is the safest recovery since
    the table is already there.
    """
    try:
        Base.metadata.create_all(_engine, checkfirst=True)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "create_all raised (likely tables already exist, continuing): %s", exc
        )


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a scoped session per request."""
    session: Session = _SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def session_factory() -> Session:
    """Direct factory for code paths that aren't FastAPI routes."""
    return _SessionLocal()
