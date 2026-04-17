"""Shared Jinja2 templates + base context helper.

Split from ``main.py`` so every admin-UI router can import the same
``Templates`` instance without a circular dependency back through the
FastAPI app object. ``base_context`` always includes the CSRF cookie
value + version so the ``base.html`` layout renders regardless of which
route triggered the render.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from . import __version__


_APP_DIR = Path(__file__).parent

templates = Jinja2Templates(directory=_APP_DIR / "templates")


def _current_banner() -> str | None:
    """Fetch the GlobalPolicy banner message lazily.

    Kept dead-simple (one short query per admin page render) because the
    singleton table is ~100 bytes and hits the SQLAlchemy identity map
    cache after the first read. If that ever shows up on a flame graph,
    wrap it in a TTLCache next to catalog_response_cache.
    """
    try:
        from .db import GlobalPolicy, session_factory

        with session_factory() as db:
            row = db.get(GlobalPolicy, 1)
            if row is None:
                return None
            msg = (row.banner_message or "").strip()
            return msg or None
    except Exception:  # noqa: BLE001
        # Never let the banner break a page render — if the DB is down,
        # the health probe already reports it.
        return None


def base_context(request: Request, username: str | None, **extra) -> dict:
    """Shared template context — version always present so base.html renders.

    Includes the active CSRF token so admin templates can embed it as a
    hidden input on every form. The cookie itself is refreshed by the
    GET handler right before the template renders. Also injects the
    current banner message so ``base.html`` can render it above every
    admin page.
    """
    # First-visit bootstrap: when the CSRF cookie isn't present yet,
    # mint a token now and stash it on request.state so the middleware
    # that sets the cookie picks the same value up. Without this, the
    # form would render with an empty token while the middleware writes
    # a fresh random one — every first POST would fail CSRF.
    csrf = request.cookies.get("nks_wdc_csrf") or ""
    if not csrf or len(csrf) < 32:
        existing_state = getattr(request.state, "csrf_token", None)
        if existing_state:
            csrf = existing_state
        else:
            import secrets as _secrets

            csrf = _secrets.token_urlsafe(32)
            request.state.csrf_token = csrf
    theme = request.cookies.get("nks_wdc_theme")
    if theme not in ("light", "dark"):
        theme = ""  # empty = fall through to prefers-color-scheme
    ctx = {
        "request": request,
        "username": username,
        "version": __version__,
        "flash": None,
        "csrf_token": csrf,
        "banner": _current_banner(),
        "theme": theme,
    }
    ctx.update(extra)
    return ctx


__all__ = ["templates", "base_context"]
