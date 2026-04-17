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


def base_context(request: Request, username: str | None, **extra) -> dict:
    """Shared template context — version always present so base.html renders.

    Includes the active CSRF token so admin templates can embed it as a
    hidden input on every form. The cookie itself is refreshed by the
    GET handler right before the template renders.
    """
    csrf = request.cookies.get("nks_wdc_csrf") or ""
    ctx = {
        "request": request,
        "username": username,
        "version": __version__,
        "flash": None,
        "csrf_token": csrf,
    }
    ctx.update(extra)
    return ctx


__all__ = ["templates", "base_context"]
