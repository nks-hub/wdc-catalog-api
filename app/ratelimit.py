"""Shared slowapi Limiter instance — imported by main.py and devices.py.

Keeping the limiter in its own module avoids a circular import between
main.py (which mounts devices_router) and devices.py (which needs
@limiter.limit decorators on /auth endpoints).

Tests set NKS_WDC_DISABLE_RATE_LIMITS=1 so assertions aren't flaky from
per-IP counters bleeding between test functions.

Set NKS_WDC_RATELIMIT_REDIS=redis://host:6379/0 to share counters across
workers/instances. Without it slowapi uses an in-memory store scoped to a
single process — safe for single-worker deploys, incorrect once you run
multiple workers or replicas.

Set NKS_WDC_TRUSTED_PROXIES to a comma-separated list of proxy CIDRs (or
the literal string ``*``) to trust ``X-Forwarded-For`` and derive the
client IP from the *first* hop. Without this env every request behind a
proxy looks like one IP → a single noisy client would DoS the shared
rate-limit budget for everyone.
"""

from __future__ import annotations

import ipaddress
import os
from typing import Optional

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

_DISABLED = os.environ.get("NKS_WDC_DISABLE_RATE_LIMITS") == "1"
_STORAGE_URI = os.environ.get("NKS_WDC_RATELIMIT_REDIS") or "memory://"


def _parse_trusted_proxies() -> list:
    raw = os.environ.get("NKS_WDC_TRUSTED_PROXIES", "").strip()
    if not raw:
        return []
    if raw == "*":
        return ["*"]
    out: list = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            out.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return out


_TRUSTED = _parse_trusted_proxies()


def _peer_is_trusted(peer: Optional[str]) -> bool:
    if not _TRUSTED or peer is None:
        return False
    if _TRUSTED == ["*"]:
        return True
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(ip in net for net in _TRUSTED if net != "*")


def client_ip(request: Request) -> str:
    """Return the real client IP, honouring XFF only from trusted peers.

    When the immediate TCP peer is *not* in ``NKS_WDC_TRUSTED_PROXIES``
    we fall back to the socket address — so spoofed XFF headers from
    untrusted clients are ignored.
    """
    peer = request.client.host if request.client else None
    if _peer_is_trusted(peer):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # First hop in XFF is the original client (per RFC 7239).
            return xff.split(",")[0].strip() or peer or "0.0.0.0"
    return peer or "0.0.0.0"


def _ratelimit_key(request: Request) -> str:
    # Delegate to client_ip when proxy trust is configured; otherwise
    # preserve slowapi's default behaviour (request.client.host) so
    # unconfigured deployments don't change semantics.
    if _TRUSTED:
        return client_ip(request)
    return get_remote_address(request)


limiter = Limiter(
    key_func=_ratelimit_key,
    enabled=not _DISABLED,
    default_limits=[],
    storage_uri=_STORAGE_URI,
)
