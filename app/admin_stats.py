"""Admin statistics dashboard — aggregate counts for catalog + users."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import (
    Account,
    App,
    AuditEvent,
    DeviceConfig,
    Download,
    Release,
    User,
    get_session,
)
from .permissions import require_role
from .roles import Role

router = APIRouter(prefix="/api/v1/admin/stats", tags=["admin:stats"])


class CatalogStats(BaseModel):
    apps: int
    releases: int
    downloads: int


class UserStats(BaseModel):
    accounts_total: int
    accounts_suspended: int
    accounts_by_role: dict[str, int]
    admin_ui_users: int
    devices: int
    devices_linked: int
    devices_online_recent: int


class AuditStats(BaseModel):
    events_total: int
    events_last_24h: int
    top_actions: list[dict]


class OverviewResponse(BaseModel):
    catalog: CatalogStats
    users: UserStats
    audit: AuditStats
    generated_at: str


def build_overview(db: Session) -> OverviewResponse:
    """Core overview-builder used by both the JSON endpoint + HTML dashboard.

    Cached in-process for 30 s. The dashboard refreshes manually and
    10+ COUNT(*) queries per hit was overkill.
    """
    from ._cache import stats_overview_cache

    cached = stats_overview_cache.get("overview")
    if cached is not None:
        return cached

    now = datetime.now(timezone.utc)
    five_min_ago = now - timedelta(minutes=5)
    day_ago = now - timedelta(hours=24)

    # Catalog counters — one round-trip with scalar subqueries so
    # Postgres can parallelize the three table counts.
    catalog_row = db.execute(
        select(
            select(func.count(App.id)).scalar_subquery().label("apps"),
            select(func.count(Release.id)).scalar_subquery().label("releases"),
            select(func.count(Download.id)).scalar_subquery().label("downloads"),
        )
    ).one()
    catalog = CatalogStats(
        apps=catalog_row.apps or 0,
        releases=catalog_row.releases or 0,
        downloads=catalog_row.downloads or 0,
    )

    # Account counters — total + suspended in one query.
    # ``count(col)`` counts non-NULL values, so ``count(suspended_at)``
    # gives us the suspended-count for free.
    acct_row = db.execute(
        select(
            func.count(Account.id).label("total"),
            func.count(Account.suspended_at).label("suspended"),
        )
    ).one()

    by_role_rows = db.execute(
        select(Account.role, func.count(Account.id)).group_by(Account.role)
    ).all()
    by_role = {role: count for role, count in by_role_rows}

    # Device counters. ``nullif(predicate, False)`` returns NULL when the
    # predicate is False, so the surrounding COUNT skips it — giving a
    # portable conditional count without Postgres-only FILTER.
    dev_row = db.execute(
        select(
            func.count(DeviceConfig.device_id).label("total"),
            func.count(DeviceConfig.user_id).label("linked"),
            func.count(
                func.nullif(DeviceConfig.last_seen_at > five_min_ago, False)
            ).label("online"),
        )
    ).one()

    users = UserStats(
        accounts_total=acct_row.total or 0,
        accounts_suspended=acct_row.suspended or 0,
        accounts_by_role=by_role,
        admin_ui_users=db.scalar(select(func.count(User.id))) or 0,
        devices=dev_row.total or 0,
        devices_linked=dev_row.linked or 0,
        devices_online_recent=dev_row.online or 0,
    )

    # Audit totals + last-24h in one query.
    audit_row = db.execute(
        select(
            func.count(AuditEvent.id).label("total"),
            func.count(func.nullif(AuditEvent.created_at > day_ago, False)).label(
                "last_24h"
            ),
        )
    ).one()
    top_actions_rows = db.execute(
        select(AuditEvent.action, func.count(AuditEvent.id))
        .group_by(AuditEvent.action)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
    ).all()
    audit_stats = AuditStats(
        events_total=audit_row.total or 0,
        events_last_24h=audit_row.last_24h or 0,
        top_actions=[{"action": a, "count": c} for a, c in top_actions_rows],
    )

    response = OverviewResponse(
        catalog=catalog,
        users=users,
        audit=audit_stats,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
    stats_overview_cache.set("overview", response)
    return response


@router.get("/overview", response_model=OverviewResponse)
def overview(
    _: Account = Depends(require_role(Role.support)),
    db: Session = Depends(get_session),
) -> OverviewResponse:
    """Aggregate counters for the admin dashboard (JSON, support+)."""
    return build_overview(db)


__all__ = ["router", "build_overview"]
