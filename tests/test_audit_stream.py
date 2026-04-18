"""Tests for GET /admin/audit/stream SSE endpoint.

Starlette's TestClient drives requests via ``portal.call()`` which blocks
the test thread until the ASGI app coroutine returns.  For an infinite SSE
generator that never returns, this would deadlock.

Strategy: pull ``client.portal`` (the anyio BlockingPortal) from the
TestClient and run a ``portal.call(_run)`` coroutine that drives the ASGI
app directly *inside* the portal's event loop using anyio task groups.
Because the SSE generator and the audit emitter both run as tasks in the
same event loop, asyncio.Queue.put_nowait() wakes up the awaiting get()
without any cross-thread signalling issues.
"""

from __future__ import annotations

import anyio
from fastapi.testclient import TestClient

from app.main import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_totp() -> None:
    """Disable TOTP on admin so the login path is straightforward."""
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    with session_factory() as db:
        acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
        if acct is not None:
            acct.totp_enabled = False
            acct.totp_secret = None
            acct.totp_recovery_hashes = None
            acct.totp_enabled_at = None
            db.commit()


def _login(client: TestClient) -> None:
    client.get("/login")
    csrf = client.cookies.get("nks_wdc_csrf") or ""
    r = client.post(
        "/login",
        data={"username": "admin", "password": "admin", "_csrf": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 303, f"login failed: {r.status_code}"


def _http_scope(cookie_header: str) -> dict:
    """Minimal ASGI HTTP scope for GET /admin/audit/stream."""
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": "/admin/audit/stream",
        "raw_path": b"/admin/audit/stream",
        "query_string": b"",
        "headers": [(b"cookie", cookie_header.encode())],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "scheme": "http",
        "root_path": "",
        "state": {},
    }


async def _sse_session(
    cookie_header: str,
    *,
    stop_ev: anyio.Event,
    lines_out: list[str],
) -> dict:
    """Drive the SSE ASGI endpoint inside the current anyio event loop.

    Collects decoded SSE lines into *lines_out* until *stop_ev* is set (by
    the caller) or the generator closes.  Returns the response info dict.
    """
    send_tx, send_rx = anyio.create_memory_object_stream(max_buffer_size=100)
    request_complete = anyio.Event()
    response_started = anyio.Event()
    response_info: dict = {}
    body_done = anyio.Event()

    async def receive():
        await request_complete.wait()
        await body_done.wait()
        return {"type": "http.disconnect"}

    async def send_msg(message):
        if message["type"] == "http.response.start":
            response_info["status"] = message["status"]
            response_info["headers"] = dict(message.get("headers", []))
            response_started.set()
        elif message["type"] == "http.response.body":
            body = message.get("body", b"")
            more = message.get("more_body", False)
            if body:
                await send_tx.send(body)
            if not more:
                await send_tx.aclose()
                body_done.set()

    request_complete.set()
    buf = b""

    async def _consume(cs: anyio.CancelScope):
        nonlocal buf
        await response_started.wait()
        async for chunk in send_rx:
            buf += chunk
            for ln in buf.decode("utf-8", errors="replace").split("\n"):
                if ln and ln not in lines_out:
                    lines_out.append(ln)
            if stop_ev.is_set():
                cs.cancel()
                return

    with anyio.CancelScope() as cs:
        async with anyio.create_task_group() as tg:
            tg.start_soon(lambda: app(_http_scope(cookie_header), receive, send_msg))
            tg.start_soon(lambda: _consume(cs))

    return response_info


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_unauthenticated_client_denied() -> None:
    """No session cookie → redirect to /login (302) or 401."""
    with TestClient(app, follow_redirects=False) as c:
        r = c.get("/admin/audit/stream")
    assert r.status_code in (302, 303, 401), (
        f"expected auth redirect or 401, got {r.status_code}"
    )
    if r.status_code in (302, 303):
        assert "/login" in r.headers.get("location", "")


def test_connected_event_sent_immediately() -> None:
    """The first SSE frame must be ``event: connected``."""
    _reset_totp()
    collected: list[str] = []

    with TestClient(app) as c:
        _login(c)
        cookie_header = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
        portal = c.portal
        assert portal is not None

        async def _run() -> None:
            stop = anyio.Event()

            async def _watch() -> None:
                while True:
                    await anyio.sleep(0.05)
                    if any("event: connected" in ln for ln in collected):
                        stop.set()
                        return

            with anyio.fail_after(5.0):
                async with anyio.create_task_group() as tg:
                    tg.start_soon(_watch)
                    tg.start_soon(lambda: _sse_session(cookie_header, stop_ev=stop, lines_out=collected))
                    await stop.wait()
                    tg.cancel_scope.cancel()

        portal.call(_run)

    assert any("event: connected" in ln for ln in collected), (
        f"connected frame not found; collected={collected!r}"
    )
    assert any("data: {}" in ln for ln in collected), (
        f"data: {{}} not found; collected={collected!r}"
    )


def test_authenticated_client_receives_event() -> None:
    """After subscribing, ``audit.emit()`` must produce an ``event: audit`` frame."""
    from app import audit
    from app.db import Account, session_factory
    from sqlalchemy import select as _sel

    _reset_totp()
    collected: list[str] = []

    with TestClient(app) as c:
        _login(c)
        cookie_header = "; ".join(f"{k}={v}" for k, v in c.cookies.items())
        portal = c.portal
        assert portal is not None

        async def _run() -> None:
            stop = anyio.Event()
            connected_ev = anyio.Event()

            async def _watch() -> None:
                while True:
                    await anyio.sleep(0.05)
                    if not connected_ev.is_set() and any("event: connected" in ln for ln in collected):
                        connected_ev.set()
                    if any("event: audit" in ln for ln in collected):
                        stop.set()
                        return

            async def _emit() -> None:
                await connected_ev.wait()
                await anyio.sleep(0.1)
                with session_factory() as db:
                    acct = db.scalar(_sel(Account).where(Account.email == "admin@admin.local"))
                    audit.emit(
                        db,
                        actor=acct,
                        action="test.sse_delivery",
                        resource_type="test",
                        resource_id="sse-1",
                    )
                    db.commit()

            with anyio.fail_after(6.0):
                async with anyio.create_task_group() as tg:
                    tg.start_soon(_watch)
                    tg.start_soon(_emit)
                    tg.start_soon(lambda: _sse_session(cookie_header, stop_ev=stop, lines_out=collected))
                    await stop.wait()
                    tg.cancel_scope.cancel()

        portal.call(_run)

    assert any("event: audit" in ln for ln in collected), (
        f"event: audit not found; collected={collected!r}"
    )
    assert any("sse_delivery" in ln for ln in collected), (
        f"action not in data; collected={collected!r}"
    )
