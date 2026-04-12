"""Tests for catalog service CRUD operations.

Re-uses the state dir from test_devices.py (set at import-time in conftest
or the first test module). The SQLAlchemy engine is a module-level singleton
so setting NKS_WDC_CATALOG_STATE_DIR again would be ignored anyway.
"""

from __future__ import annotations

from app.db import create_all, session_factory, App
from app.service import create_app, list_apps
from sqlalchemy import select


class TestServiceCRUD:
    def test_create_app_returns_app(self):
        import uuid
        create_all()
        app_id = f"test-crud-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            app = create_app(db, app_id=app_id, display_name="Test CRUD")
            assert app.id == app_id

    def test_list_apps_includes_created(self):
        import uuid
        create_all()
        app_id = f"list-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            create_app(db, app_id=app_id, display_name="List Test")
            db.commit()
        with session_factory() as db:
            apps = list_apps(db)
            ids = [a.id for a in apps]
            assert app_id in ids

    def test_create_duplicate_raises(self):
        import uuid, pytest
        create_all()
        app_id = f"dup-{uuid.uuid4().hex[:6]}"
        with session_factory() as db:
            create_app(db, app_id=app_id, display_name="V1")
            db.commit()
        with session_factory() as db:
            with pytest.raises(Exception):
                create_app(db, app_id=app_id, display_name="V2")
                db.flush()
