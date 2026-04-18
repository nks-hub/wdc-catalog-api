"""Regression — ``db._literal_default`` + per-column auto-ALTER must
derive working DEFAULT clauses for NOT NULL column shapes we ship.

Incident 2026-04-18 (v0.48.2 hotfix): SQLite rejected
``ALTER TABLE accounts ADD COLUMN totp_enabled BOOLEAN NOT NULL`` with
no literal DEFAULT, and the whole loop rolled back, leaving prod
half-migrated. Per-column try + derived DEFAULT fixed it; these tests
pin the contract so future NOT NULL columns don't regress the flow.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import Column, DateTime, Integer, String, Boolean

from app.db import _literal_default, _utc_now


def _col(type_, default=None, nullable=False):
    """Build a bare Column with the default shape we want to test."""
    return Column(type_, default=default, nullable=nullable)


def test_literal_default_for_true_bool() -> None:
    assert _literal_default(_col(Boolean, default=True)) == "1"


def test_literal_default_for_false_bool() -> None:
    assert _literal_default(_col(Boolean, default=False)) == "0"


def test_literal_default_for_int() -> None:
    assert _literal_default(_col(Integer, default=7)) == "7"


def test_literal_default_for_str_escapes_single_quotes() -> None:
    assert _literal_default(_col(String(32), default="it's")) == "'it''s'"


def test_literal_default_for_datetime_callable_emits_current_timestamp() -> None:
    """Callable default on a DateTime column must fall back to
    ``CURRENT_TIMESTAMP`` — not None — otherwise the auto-ALTER path
    would silently skip the column on prod."""
    assert _literal_default(_col(DateTime, default=_utc_now)) == "CURRENT_TIMESTAMP"


def test_literal_default_for_arbitrary_callable_returns_none() -> None:
    """Non-timestamp callables can't be safely rendered — return None
    so the caller emits the ALTER without a DEFAULT, then per-column
    try-catch handles the (likely) SQLite rejection visibly in logs."""
    assert _literal_default(_col(Integer, default=lambda: 42)) is None


def test_literal_default_for_column_without_default_returns_none() -> None:
    assert _literal_default(_col(Integer)) is None
