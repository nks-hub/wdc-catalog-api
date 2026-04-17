"""Admin statistics dashboard — aggregate counts for catalog + users."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

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


@router.get("/overview", response_model=OverviewResponse)
def overview(
    _: Account = Depends(require_role(Role.support)),
    db: Session = Depends(get_session),
) -> OverviewResponse:
    """Aggregate counters for the admin dashboard. Support role or higher.

    Cached in-process for 30 s. The dashboard refreshes manually and
    10+ COUNT(*) queries per hit was overkill.
    """
    from ._cache import stats_overview_cache
    cached = stats_overview_cache.get("overview")
    if cached is not None:
        return cached
    catalog = CatalogStats(
        apps=db.scalar(select(func.count(App.id))) or 0,
        releases=db.scalar(select(func.count(Release.id))) or 0,
        downloads=db.scalar(select(func.count(Download.id))) or 0,
    )

    by_role_rows = db.execute(
        select(Account.role, func.count(Account.id)).group_by(Account.role)
    ).all()
    by_role = {role: count for role, count in by_role_rows}

    five_min_ago = datetime.now(timezone.utc) - timedelta(minutes=5)
    users = UserStats(
        accounts_total=db.scalar(select(func.count(Account.id))) or 0,
        accounts_suspended=db.scalar(
            select(func.count(Account.id)).where(Account.suspended_at.is_not(None))
        ) or 0,
        accounts_by_role=by_role,
        admin_ui_users=db.scalar(select(func.count(User.id))) or 0,
        devices=db.scalar(select(func.count(DeviceConfig.device_id))) or 0,
        devices_linked=db.scalar(
            select(func.count(DeviceConfig.device_id)).where(DeviceConfig.user_id.is_not(None))
        ) or 0,
        devices_online_recent=db.scalar(
            select(func.count(DeviceConfig.device_id)).where(
                DeviceConfig.last_seen_at.is_not(None),
                DeviceConfig.last_seen_at > five_min_ago,
            )
        ) or 0,
    )

    day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    top_actions_rows = db.execute(
        select(AuditEvent.action, func.count(AuditEvent.id))
        .group_by(AuditEvent.action)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
    ).all()
    audit_stats = AuditStats(
        events_total=db.scalar(select(func.count(AuditEvent.id))) or 0,
        events_last_24h=db.scalar(
            select(func.count(AuditEvent.id)).where(AuditEvent.created_at > day_ago)
        ) or 0,
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


__all__ = ["router"]
