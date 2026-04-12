"""Tests for catalog service CRUD operations."""

from __future__ import annotations
import os
import tempfile

os.environ["NKS_WDC_CATALOG_STATE_DIR"] = tempfile.mkdtemp(prefix="nks-wdc-svc-test-")
os.environ["NKS_WDC_CATALOG_DEV"] = "1"

from app.db import create_all, session_factory, App
from app.service import create_app, list_apps
from sqlalchemy import select


class TestServiceCRUD:
    def test_create_app_returns_app(self):
        create_all()
        with session_factory() as db:
            app = create_app(db, app_id="test-crud", display_name="Test CRUD")
            assert app.id == "test-crud"
            assert app.display_name == "Test CRUD"

    def test_list_apps_includes_created(self):
        create_all()
        with session_factory() as db:
            create_app(db, app_id="list-test", display_name="List Test")
            db.commit()
        with session_factory() as db:
            apps = list_apps(db)
            ids = [a.id for a in apps]
            assert "list-test" in ids

    def test_create_duplicate_raises(self):
        import pytest
        create_all()
        with session_factory() as db:
            create_app(db, app_id="dup-test", display_name="V1")
            db.commit()
        with session_factory() as db:
            with pytest.raises(Exception):
                create_app(db, app_id="dup-test", display_name="V2")
                db.flush()
