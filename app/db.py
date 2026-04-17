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
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    SmallInteger,
    String,
    Text,
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
_SessionLocal = sessionmaker(
    bind=_engine, autoflush=False, autocommit=False, future=True
)


# SQLite disables foreign-key enforcement by default, so all our
# ``ondelete='SET NULL' / 'CASCADE'`` declarations would be silently
# ignored. Turn it on for every new connection so deleting an account
# actually nulls out ``audit_events.actor_id`` instead of leaving
# dangling rows that point to nonexistent account ids.
if "sqlite" in _database_url():
    from sqlalchemy import event as _sa_event

    @_sa_event.listens_for(_engine, "connect")
    def _enable_sqlite_fk(dbapi_conn, _conn_record):  # type: ignore[no-redef]
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()


class Base(DeclarativeBase):
    pass


def count_query(db: "Session", stmt) -> int:
    """Portable COUNT helper for a filtered SELECT statement.

    Avoids the ``select(func.count()).select_from(stmt.subquery())``
    pattern which on SQLite materializes a temp table and on Postgres
    can confuse the optimizer with JOINs. Strips ORDER BY / LIMIT /
    OFFSET before counting since they don't affect the cardinality.
    """
    from sqlalchemy import func  # local import to keep module top tidy

    count_stmt = (
        stmt.with_only_columns(func.count()).order_by(None).limit(None).offset(None)
    )
    return db.scalar(count_stmt) or 0


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
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, onupdate=_utc_now
    )

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
    app_id: Mapped[str] = mapped_column(
        ForeignKey("apps.id", ondelete="CASCADE"), index=True
    )
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
            "release_id",
            "os",
            "arch",
            "archive_type",
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
    role: Mapped[str] = mapped_column(String(16), default="user", nullable=False)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    token_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Account-lockout bookkeeping. Counter increments on every failed
    # password check and resets on successful auth. ``locked_until`` holds
    # an absolute UTC instant; the login handler refuses while it's in
    # the future, decouples from the shared rate-limit key so a single
    # noisy proxy can't force every user out.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # TOTP two-factor authentication — opt-in per account. The login flow
    # treats ``totp_enabled`` as the gate; ``totp_secret`` is only
    # populated once the user confirms a first code (a secret sitting in
    # the row without the flag means setup was started but never
    # finished — a later "disable & retry" clears both). Recovery codes
    # are stored as a newline-joined list of bcrypt hashes so a DB leak
    # never surfaces the plaintext fallback codes.
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    totp_recovery_hashes: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_enabled_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IdempotencyRecord(Base):
    """Cached response for ``Idempotency-Key``-tagged POST requests.

    A hit returns the stored ``response_body`` + ``status_code`` verbatim
    so a network retry lands on the same result without duplicating the
    mutation (critical for snapshot create / invite mint / restore).
    Old rows are pruned by the retention runner (``expires_at`` column).
    """

    __tablename__ = "idempotency_records"

    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    method: Mapped[str] = mapped_column(String(8))
    path: Mapped[str] = mapped_column(String(256))
    # sha256 of the raw request body. Used to detect retries that reuse
    # the same Idempotency-Key with a *different* payload — those are
    # programmer errors and we 422 instead of silently replaying the old
    # response. Nullable for legacy rows written before this column
    # existed; missing hash means skip the check (backward-compat read).
    body_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status_code: Mapped[int] = mapped_column(Integer)
    response_body: Mapped[bytes] = mapped_column(LargeBinary)
    content_type: Mapped[str] = mapped_column(String(64), default="application/json")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class RevokedToken(Base):
    """Denylist of JWT jti values that must be rejected even if the
    signature + expiry check would otherwise pass. Populated on logout,
    password change, account suspension, and admin-initiated revocation."""

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True, index=True
    )


class PersonalAccessToken(Base):
    """User-owned API keys for CI/scripts that can't run the
    interactive ``/auth/login`` flow.

    The plaintext value is a URL-safe random string prefixed with
    ``nks_pat_`` so the bearer-auth middleware can distinguish it from
    JWTs at glance. Only the bcrypt hash is persisted; plaintext is
    returned once at creation time and then discarded.
    """

    __tablename__ = "personal_access_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Bcrypt hash of the plaintext token — verified on every request via
    # ``bcrypt.checkpw``. Cost factor follows ``NKS_WDC_BCRYPT_ROUNDS``.
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    # Short prefix (first 10 chars of plaintext) kept in clear so the UI
    # can display an identifier even after revocation. Never enough to
    # recover the full token.
    token_prefix: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ConsumedInvite(Base):
    """Tracks invite nonces that have been redeemed so the same signed
    token can never be replayed — even after the created account has
    been deleted by an admin.

    The invite token itself is a signed blob with a ``nonce`` UUID; we
    persist that nonce on successful ``accept-invite`` so future attempts
    with the same token hit this row and 409 out.
    """

    __tablename__ = "consumed_invites"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(128), index=True)
    consumed_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    account_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
    )


class GlobalPolicy(Base):
    """Singleton settings row (``id=1``) holding instance-wide policy
    defaults. Seeded with a conservative baseline on first startup."""

    __tablename__ = "global_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    snapshot_keep_last_n: Mapped[int] = mapped_column(Integer, default=30)
    snapshot_retain_days: Mapped[int] = mapped_column(Integer, default=90)
    max_bytes_per_user: Mapped[int | None] = mapped_column(Integer, nullable=True)
    registration_enabled: Mapped[bool] = mapped_column(default=True)
    default_role: Mapped[str] = mapped_column(String(16), default="user")
    banner_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, onupdate=_utc_now
    )
    updated_by_email: Mapped[str | None] = mapped_column(String(128), nullable=True)


class AuditEvent(Base):
    """Append-only audit trail for admin + security actions.

    Every mutation that crosses a trust boundary (role change, suspend,
    password reset, account delete, etc.) emits one of these. Rows are
    immutable — no UPDATE path — so the trail survives tampering by
    anyone without DB-level write access.
    """

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    actor_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_email: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, index=True)


class DeviceConfig(Base):
    __tablename__ = "device_configs"

    device_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    os: Mapped[str | None] = mapped_column(String(16), nullable=True)
    arch: Mapped[str | None] = mapped_column(String(16), nullable=True)
    site_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, onupdate=_utc_now
    )
    payload: Mapped[dict] = mapped_column(JSON)


class DeviceSnapshot(Base):
    """Immutable per-sync snapshot of a device's configuration payload.

    Rows never UPDATE (barring the retention runner's DELETE). HEAD lives
    separately in ``device_heads`` so restore is a pointer move, not a copy.
    Exactly one of ``payload_json`` / ``payload_blob`` / ``blob_uri`` is
    populated — the first lane wins for small configs (< 64 KB), the
    middle for compressed/encrypted medium payloads, the third reserves
    future external object-storage backends.
    """

    __tablename__ = "device_snapshots"
    __table_args__ = (
        CheckConstraint(
            "(CASE WHEN payload_json IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN payload_blob IS NOT NULL THEN 1 ELSE 0 END) + "
            "(CASE WHEN blob_uri IS NOT NULL THEN 1 ELSE 0 END) = 1",
            name="ck_snapshot_exactly_one_storage",
        ),
        CheckConstraint(
            "kind IN ('auto','manual','pre_restore','import')",
            name="ck_snapshot_kind",
        ),
        Index("ix_snap_device_created", "device_id", "created_at"),
        Index("ix_snap_account_kind_created", "account_id", "kind", "created_at"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    device_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("device_configs.device_id", ondelete="CASCADE"),
        nullable=False,
    )
    account_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, nullable=False
    )
    label: Mapped[str | None] = mapped_column(String(128), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="auto", nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    # ``none_as_null=True`` makes Python ``None`` persist as SQL NULL
    # rather than the JSON literal string ``null`` — required for the
    # exactly-one-storage CHECK constraint.
    payload_json: Mapped[dict | None] = mapped_column(
        JSON(none_as_null=True), nullable=True
    )
    payload_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    blob_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_snapshot_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("device_snapshots.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    compression: Mapped[str | None] = mapped_column(String(8), nullable=True)
    encryption_kid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)


class DeviceHead(Base):
    """HEAD pointer per device — which snapshot is currently authoritative.

    Keeping this in a dedicated table (rather than a column on
    ``device_configs``) lets us swap HEAD atomically and audit each move
    without touching the larger row.
    """

    __tablename__ = "device_heads"

    device_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("device_configs.device_id", ondelete="CASCADE"),
        primary_key=True,
    )
    current_snapshot_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("device_snapshots.id", ondelete="RESTRICT"),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=_utc_now,
        onupdate=_utc_now,
        nullable=False,
    )
    updated_by: Mapped[str] = mapped_column(String(32), default="sync", nullable=False)


class SnapshotRetentionPolicy(Base):
    """Per-account + optional per-device retention settings.

    ``device_id=None`` → account-wide default. Resolution priority:
    device-specific > account-wide > global policy > hardcoded fallback.
    """

    __tablename__ = "snapshot_retention_policies"
    __table_args__ = (
        UniqueConstraint("account_id", "device_id", name="uq_retention_scope"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    account_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="CASCADE"),
        index=True,
    )
    device_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("device_configs.device_id", ondelete="CASCADE"),
        nullable=True,
    )
    keep_last_n_auto: Mapped[int] = mapped_column(SmallInteger, default=30)
    auto_expire_days: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    keep_labeled_forever: Mapped[bool] = mapped_column(Boolean, default=True)
    max_total_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, onupdate=_utc_now
    )


class SnapshotExport(Base):
    """Audit trail for snapshot exports + restores + imports."""

    __tablename__ = "snapshot_exports"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    account_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="CASCADE"),
        index=True,
    )
    snapshot_id: Mapped[int | None] = mapped_column(
        BigInteger,
        ForeignKey("device_snapshots.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now, index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(256), nullable=True)
    notes: Mapped[str | None] = mapped_column(String(512), nullable=True)


class AccountEncryptionKey(Base):
    """Envelope-encryption metadata — DEK wrapped by account KEK."""

    __tablename__ = "account_encryption_keys"

    kid: Mapped[str] = mapped_column(String(64), primary_key=True)
    account_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("accounts.id", ondelete="CASCADE"),
        index=True,
    )
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrap_algo: Mapped[str] = mapped_column(String(32), default="aes-256-gcm")
    kek_source: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Partial unique index on (account_id, kek_source) WHERE retired_at IS
    # NULL — created via the Alembic migration (uses raw CREATE UNIQUE
    # INDEX so the WHERE clause passes through verbatim on both Postgres
    # and SQLite). Declarative ``__table_args__`` is intentionally empty:
    # SQLAlchemy's Index kwargs accept strings but emit them through the
    # compiler, which trips up on ``CREATE TABLE … embedded`` paths used
    # by ``create_all`` for SQLite tests.


# ── Session helper ──────────────────────────────────────────────────────


def create_all() -> None:
    """Idempotent schema creation + auto-ALTER on startup.

    ``Base.metadata.create_all(checkfirst=True)`` only creates missing
    *tables* — it does not add new *columns* to tables that predate them.
    On long-lived deployments (where the DB file was created before the
    role system existed) this left ``accounts.role`` etc. missing, and
    routes that referenced the new columns 500'd at query time.

    This helper diffs declared vs actual columns on every existing table
    and emits ``ALTER TABLE … ADD COLUMN`` for anything missing. SQLite +
    Postgres both handle it; MySQL would need minor tweaks we don't run.
    """
    import logging

    log = logging.getLogger(__name__)

    try:
        Base.metadata.create_all(_engine, checkfirst=True)
    except Exception as exc:
        log.warning(
            "create_all raised (likely tables already exist, continuing): %s", exc
        )

    # Column-level upgrade — add any missing columns to existing tables.
    # Only additive changes are safe to auto-apply; drops/renames still
    # require an explicit Alembic migration.
    from sqlalchemy import inspect, text
    from sqlalchemy.schema import CreateColumn

    try:
        insp = inspect(_engine)
        existing_tables = set(insp.get_table_names())
        with _engine.begin() as conn:
            for table_name, table in Base.metadata.tables.items():
                if table_name not in existing_tables:
                    continue
                actual_cols = {c["name"] for c in insp.get_columns(table_name)}
                for col in table.columns:
                    if col.name in actual_cols:
                        continue
                    ddl = str(
                        CreateColumn(col).compile(dialect=_engine.dialect)
                    ).strip()
                    log.warning(
                        "auto-ALTER: adding %s.%s (%s)",
                        table_name,
                        col.name,
                        col.type,
                    )
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {ddl}"))
    except Exception as exc:  # noqa: BLE001
        log.warning("column auto-upgrade skipped: %s", exc)


def get_session() -> Iterator[Session]:
    """FastAPI dependency that yields a scoped session per request.

    Semantics:
    - Handler raises (HTTPException or otherwise) → generator ``.throw()``
      reraises into the try, we rollback, propagate.
    - Handler returns normally → commit. If the commit itself errors
      (e.g., Postgres pool lost, unique-violation from a pending row)
      rollback and propagate so FastAPI's error handler sees it rather
      than an orphaned half-committed state.
    """
    session: Session = _SessionLocal()
    try:
        yield session
        try:
            session.commit()
        except Exception:
            session.rollback()
            raise
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def session_factory() -> Session:
    """Direct factory for code paths that aren't FastAPI routes."""
    return _SessionLocal()
