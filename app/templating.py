"""Shared Jinja2 templates + base context helper.

Split from ``main.py`` so every admin-UI router can import the same
``Templates`` instance without a circular dependency back through the
FastAPI app object. ``base_context`` always includes the CSRF cookie
value + version so the ``base.html`` layout renders regardless of which
route triggered the render.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from . import __version__


_APP_DIR = Path(__file__).parent

templates = Jinja2Templates(directory=_APP_DIR / "templates")


# Tokenise a pretty-printed JSON string into span-wrapped HTML so audit
# log details are scannable without JS. CSP-safe: runs at render time,
# emits static HTML. Regex below matches strings (optionally followed by
# colon → key), numbers, booleans, null, punctuation.
_JSON_TOKEN_RE = re.compile(
    r'("(?:\\.|[^"\\])*")(\s*:)?'     # 1: string, 2: colon (→ key when present)
    r'|\b(true|false|null)\b'         # 3: literal
    r'|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'  # 4: number
    r'|([{}\[\],])'                   # 5: punctuation
)


def _json_highlight(value) -> Markup:
    """Pretty-print JSON and wrap tokens in span.jsx-* classes for CSS coloring."""
    if value is None:
        return Markup("")
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return Markup('<span class="jsx-str">') + escape(value) + Markup("</span>")
    else:
        parsed = value
    pretty = json.dumps(parsed, indent=2, ensure_ascii=False, sort_keys=False)

    def replace(m: re.Match) -> str:
        s, colon, lit, num, punct = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
        if s is not None:
            cls = "jsx-key" if colon else "jsx-str"
            # All three branches return plain str — intentionally NOT Markup,
            # because Markup + str (or vice-versa) re-escapes the plain side.
            out = f'<span class="{cls}">{str(escape(s))}</span>'
            if colon:
                out += colon  # colon is `\s*:` — no HTML-special chars
            return out
        if lit is not None:
            return f'<span class="jsx-lit">{lit}</span>'
        if num is not None:
            return f'<span class="jsx-num">{num}</span>'
        return f'<span class="jsx-pun">{punct}</span>'  # punct is one of {}[],

    # Escape untouched gap text (whitespace mostly, but be safe); keep
    # everything as plain str until the final Markup() wrap so neither
    # side of an addition triggers MarkupSafe's auto-escape on the other.
    out_parts: list[str] = []
    pos = 0
    for m in _JSON_TOKEN_RE.finditer(pretty):
        out_parts.append(str(escape(pretty[pos:m.start()])))
        out_parts.append(replace(m))
        pos = m.end()
    out_parts.append(str(escape(pretty[pos:])))
    return Markup("".join(out_parts))


templates.env.filters["json_highlight"] = _json_highlight


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


def _scheduler_failure_banner() -> dict | None:
    """If ANY SchedulerRun within the last 48h has ``error IS NOT NULL``
    AND is the most-recent row for its job, surface it as a dict the
    base template renders as a red banner.

    Shape: ``{"job": "retention", "age": "3h 14m", "error": "<truncated>"}``.

    Picks the most-recent failure among all jobs so a broken retention
    run doesn't get drowned out by a subsequent successful backup — the
    operator sees the first unattended alert on every page render.
    """
    try:
        from datetime import datetime, timedelta, timezone

        from sqlalchemy import select as _sel

        from .db import SchedulerRun, session_factory

        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=48)

        with session_factory() as db:
            # One latest row per distinct job within the window; check if
            # the latest is a failure.  Small table, no materialized view
            # needed.
            jobs = db.scalars(
                _sel(SchedulerRun.job).where(
                    SchedulerRun.started_at >= cutoff
                ).distinct()
            ).all()
            newest_failure: SchedulerRun | None = None
            for job_name in jobs:
                latest = db.scalar(
                    _sel(SchedulerRun)
                    .where(SchedulerRun.job == job_name)
                    .where(SchedulerRun.started_at >= cutoff)
                    .order_by(SchedulerRun.started_at.desc())
                    .limit(1)
                )
                if latest is not None and latest.error:
                    if (
                        newest_failure is None
                        or (latest.started_at or cutoff)
                        > (newest_failure.started_at or cutoff)
                    ):
                        newest_failure = latest

            if newest_failure is None:
                return None

            age_s = (
                datetime.now(timezone.utc).replace(tzinfo=None)
                - (newest_failure.started_at or cutoff)
            ).total_seconds()
            d, rem = divmod(int(age_s), 86400)
            h, rem = divmod(rem, 3600)
            m, _s = divmod(rem, 60)
            if d:
                age_str = f"{d}d {h}h"
            elif h:
                age_str = f"{h}h {m}m"
            elif m:
                age_str = f"{m}m"
            else:
                age_str = f"{int(age_s)}s"
            err = (newest_failure.error or "").strip()
            return {
                "job": newest_failure.job,
                "age": age_str,
                "error": err[:160],  # cap so pathological tracebacks fit
            }
    except Exception:  # noqa: BLE001
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
        "scheduler_failure": _scheduler_failure_banner(),
        "theme": theme,
    }
    ctx.update(extra)
    return ctx


__all__ = ["templates", "base_context"]
