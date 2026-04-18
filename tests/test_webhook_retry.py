"""Tests for the per-row webhook retry button on /admin/ops/webhooks.

Covers the POST /admin/ops/webhooks/{delivery_id}/retry handler: 404 on
unknown id, auth + CSRF gating, success path (audit row + new
WebhookDelivery enqueued), and regression coverage for the
``webhook.retried`` SECURITY_ACTION_ALLOWLIST membership.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(autouse=True, scope="module")
def _bootstrap_db():
    with TestClient(app, client=("127.0.0.1", 50000)):
        yield


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_totp(username: str = "admin") -> None:
    from sqlalchemy import select as _sel

    from app.db import Account, GlobalPolicy, session_factory

    with session_factory() as db:
        acct = db.scalar(
            _sel(Account).where(Account.email == f"{username}@admin.local")
        )
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
        policy = db.get(GlobalPolicy, 1)
        if policy is not None and policy.require_2fa_for_admins:
            policy.require_2fa_for_admins = False
        db.commit()


def _login(
    client: TestClient, username: str = "admin", password: str = "admin"
) -> None:
    client.get("/login")
    csrf = client.cookies.get("nks_wdc_csrf") or ""
    r = client.post(
        "/login",
        data={"username": username, "password": password, "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303, f"login failed: {r.status_code} {r.text[:200]}"


def _configure_webhook(
    url: str | None = "http://127.0.0.1:1/hook",
    prefixes: str = "permission.,login.,session.,webhook.",
) -> None:
    """Seed GlobalPolicy so webhooks.fire() actually dispatches."""
    from app.db import GlobalPolicy, session_factory

    with session_factory() as db:
        policy = db.get(GlobalPolicy, 1)
        if policy is None:
            policy = GlobalPolicy(id=1)
            db.add(policy)
        policy.webhook_url = url
        policy.webhook_event_prefixes = prefixes
        db.commit()


def _seed_failed_delivery(
    url: str = "http://127.0.0.1:1/hook",
    event_action: str = "permission.denied",
    error: str = "conn refused",
) -> int:
    from app.db import WebhookDelivery, session_factory

    with session_factory() as db:
        row = WebhookDelivery(
            url=url,
            event_action=event_action,
            status_code=None,
            duration_ms=10,
            error=error,
        )
        db.add(row)
        db.flush()
        rid = row.id
        db.commit()
        return rid


def _count_audit(action: str) -> int:
    from sqlalchemy import func as _func
    from sqlalchemy import select as _sel

    from app.db import AuditEvent, session_factory

    with session_factory() as db:
        return int(
            db.scalar(
                _sel(_func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == action)
            )
            or 0
        )


def _count_deliveries() -> int:
    from sqlalchemy import func as _func
    from sqlalchemy import select as _sel

    from app.db import WebhookDelivery, session_factory

    with session_factory() as db:
        return int(db.scalar(_sel(_func.count()).select_from(WebhookDelivery)) or 0)


# ---------------------------------------------------------------------------
# Regression: allowlist membership
# ---------------------------------------------------------------------------


def test_webhook_retried_on_security_allowlist() -> None:
    from app.observability import SECURITY_ACTION_ALLOWLIST

    assert "webhook.retried" in SECURITY_ACTION_ALLOWLIST


# ---------------------------------------------------------------------------
# Unauthenticated POST must not reach handler body
# ---------------------------------------------------------------------------


def test_unauth_retry_is_rejected() -> None:
    delivery_id = _seed_failed_delivery()

    with TestClient(app) as client:
        r = client.post(
            f"/admin/ops/webhooks/{delivery_id}/retry",
            data={"_csrf": "bogus"},
            follow_redirects=False,
        )
        assert r.status_code in (303, 302, 401, 403), (
            f"Unauthenticated retry POST should bounce, got {r.status_code}"
        )


# ---------------------------------------------------------------------------
# Missing CSRF → 403
# ---------------------------------------------------------------------------


def test_retry_missing_csrf_rejected() -> None:
    delivery_id = _seed_failed_delivery()

    with TestClient(app) as client:
        _reset_totp()
        _login(client)

        r = client.post(
            f"/admin/ops/webhooks/{delivery_id}/retry",
            data={},  # no _csrf
            follow_redirects=False,
        )
        assert r.status_code == 403, (
            f"expected 403 on missing CSRF, got {r.status_code}"
        )


# ---------------------------------------------------------------------------
# 404 for unknown delivery id (authenticated)
# ---------------------------------------------------------------------------


def test_retry_unknown_delivery_id_redirects_error() -> None:
    """Handler renders a redirect with the error flash rather than a 404
    body — mirrors the pattern of other admin row-not-found handlers."""
    with TestClient(app) as client:
        _reset_totp()
        _login(client)

        csrf = client.cookies.get("nks_wdc_csrf") or ""
        r = client.post(
            "/admin/ops/webhooks/999999/retry",
            data={"_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "/admin/ops/webhooks" in r.headers.get("location", "")
        # No audit row — we bail before emitting.
        # (Can't assert exact count across tests; just ensure no crash.)


# ---------------------------------------------------------------------------
# Success path — audit row lands, new WebhookDelivery gets recorded
# ---------------------------------------------------------------------------


def test_retry_success_emits_audit_and_new_delivery() -> None:
    from app import webhooks

    _configure_webhook()
    delivery_id = _seed_failed_delivery(event_action="permission.denied")

    audit_before = _count_audit("webhook.retried")
    deliveries_before = _count_deliveries()

    with TestClient(app) as client:
        _reset_totp()
        _login(client)

        csrf = client.cookies.get("nks_wdc_csrf") or ""
        r = client.post(
            f"/admin/ops/webhooks/{delivery_id}/retry",
            data={"_csrf": csrf},
            follow_redirects=False,
        )
        assert r.status_code == 303, f"expected 303, got {r.status_code} {r.text[:200]}"
        assert "/admin/ops/webhooks" in r.headers.get("location", "")

    # Wait for the ThreadPoolExecutor to flush the POST + record a new
    # delivery row.
    webhooks.drain(timeout=5.0)
    webhooks._reset_pool_for_tests()

    audit_after = _count_audit("webhook.retried")
    deliveries_after = _count_deliveries()

    assert audit_after == audit_before + 1, (
        f"expected one new webhook.retried audit row, got delta "
        f"{audit_after - audit_before}"
    )

    # The retry enqueues a fresh POST attempt which records its own
    # delivery row (will fail fast against 127.0.0.1:1 — that's fine,
    # the recorder runs in the finally block either way).
    assert deliveries_after >= deliveries_before + 1, (
        f"expected retry to enqueue a new WebhookDelivery row; "
        f"before={deliveries_before} after={deliveries_after}"
    )

    # Confirm the audit detail carries the back-reference.
    from sqlalchemy import select as _sel

    from app.db import AuditEvent, session_factory

    with session_factory() as db:
        evt = db.scalar(
            _sel(AuditEvent)
            .where(AuditEvent.action == "webhook.retried")
            .where(AuditEvent.resource_id == str(delivery_id))
            .order_by(AuditEvent.id.desc())
            .limit(1)
        )
    assert evt is not None
    detail = evt.detail or {}
    assert detail.get("from_delivery_id") == delivery_id
    assert detail.get("event_action") == "permission.denied"
    assert "url" in detail
