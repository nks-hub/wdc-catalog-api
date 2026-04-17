"""Rate limiting regression tests — isolated from other tests so the
monkeypatched env + module reload doesn't pollute the shared `client`
fixture used by test_devices and test_smoke.
"""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def test_auth_login_rate_limited(monkeypatch) -> None:
    """F-21 guard: /auth/login must throttle at 5 req/min per IP."""
    monkeypatch.setenv("NKS_WDC_DISABLE_RATE_LIMITS", "0")
    import app.ratelimit as rl

    importlib.reload(rl)
    import app.devices as dv

    importlib.reload(dv)
    import app.main as main_mod

    importlib.reload(main_mod)
    try:
        with TestClient(main_mod.app) as c:
            for _ in range(5):
                c.post(
                    "/api/v1/auth/login",
                    json={"email": "nope@x.dev", "password": "nope"},
                )
            r = c.post(
                "/api/v1/auth/login",
                json={"email": "nope@x.dev", "password": "nope"},
            )
            assert r.status_code == 429
    finally:
        # Restore the disabled state + reload modules so subsequent tests
        # (run in a separate session but shared state dir) see the same
        # no-limit app instance the conftest expects.
        monkeypatch.setenv("NKS_WDC_DISABLE_RATE_LIMITS", "1")
        importlib.reload(rl)
        importlib.reload(dv)
        importlib.reload(main_mod)
