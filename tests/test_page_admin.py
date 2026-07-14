"""Regression tests for page_admin.py (Page Engine Phase 4N).

Covers create/update/attach/detach validation and lifecycle behaviour via a
minimal FastAPI app that registers only the Page Engine admin routes, with
get_db overridden to an isolated in-memory SQLite database (never touches the
real shadz.db). No Basic Auth is applied — verify_admin lives in main.py and
is exercised separately; these tests are scoped to page_admin.py's own logic.

Isolation note: every request in this file is served through a per-test
"sqlite:///:memory:" engine via a FastAPI get_db dependency override. Nothing
here imports main.py or touches database.engine/database.SessionLocal (the
objects bound to the real shadz.db), so no test in this file can create,
open, or write to the repository's production shadz.db file.
"""
import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
from database import Base, get_db
from page_admin import register_page_admin_routes


class PageAdminTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.SessionLocal = SessionLocal

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        register_page_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()
        self.client.close()
        self.engine.dispose()

    def _make_slug(self, slug, content_type):
        link = models.RedirectLink(slug=slug, destination_url="", content_type=content_type)
        self.db.add(link)
        self.db.commit()
        return link

    def _create_page(self, **overrides):
        payload = {"title": "Test Page", "template_type": "invitation"}
        payload.update(overrides)
        return self.client.post("/admin/pages", json=payload)

    # ── create_page ──────────────────────────────────────────────────────

    def test_create_page_rejects_invalid_template_type(self):
        res = self._create_page(template_type="not_a_real_template")
        self.assertEqual(res.status_code, 400)

    def test_create_page_rejects_invalid_status(self):
        res = self._create_page(status="published")
        self.assertEqual(res.status_code, 400)

    def test_create_page_rejects_blank_title(self):
        res = self._create_page(title="   ")
        self.assertEqual(res.status_code, 400)

    def test_create_page_succeeds_and_defaults_status_to_draft(self):
        res = self._create_page()
        self.assertEqual(res.status_code, 201)

        rows = self.db.query(models.Page).all()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.title, "Test Page")
        self.assertEqual(row.template_type, "invitation")
        self.assertEqual(row.status, "draft")

    # ── update_page ──────────────────────────────────────────────────────

    def test_update_page_partial_update_preserves_omitted_fields(self):
        created = self._create_page(title="Original", template_type="brand_product").json()
        res = self.client.post(f"/admin/pages/{created['id']}", json={"status": "ready"})
        self.assertEqual(res.status_code, 200)

        row = self.db.query(models.Page).filter(models.Page.id == created["id"]).one()
        self.assertEqual(row.status, "ready")
        self.assertEqual(row.title, "Original")
        self.assertEqual(row.template_type, "brand_product")

    def test_update_page_rejects_invalid_template_type(self):
        created = self._create_page().json()
        res = self.client.post(
            f"/admin/pages/{created['id']}", json={"template_type": "bogus"}
        )
        self.assertEqual(res.status_code, 400)

    def test_update_page_rejects_invalid_status(self):
        created = self._create_page().json()
        res = self.client.post(f"/admin/pages/{created['id']}", json={"status": "bogus"})
        self.assertEqual(res.status_code, 400)

    def test_update_page_rejects_blank_title(self):
        created = self._create_page().json()
        res = self.client.post(f"/admin/pages/{created['id']}", json={"title": "   "})
        self.assertEqual(res.status_code, 400)

    def test_update_page_missing_page_id_returns_404(self):
        res = self.client.post("/admin/pages/999999", json={"title": "x"})
        self.assertEqual(res.status_code, 404)

    def test_update_page_bumps_updated_at_on_change(self):
        created = self._create_page().json()

        # Force a deterministic starting point instead of relying on two
        # datetime.now(timezone.utc) calls landing in different instants —
        # avoids clock-resolution flakiness on fast/CI runs. SQLite round-trips
        # DateTime(timezone=True) as naive, so the sentinel is naive too.
        sentinel = datetime.datetime(2020, 1, 1)
        row = self.db.query(models.Page).filter(models.Page.id == created["id"]).one()
        row.updated_at = sentinel
        self.db.commit()

        res = self.client.post(f"/admin/pages/{created['id']}", json={"title": "New Title"})
        self.assertEqual(res.status_code, 200)

        refreshed = (
            self.db.query(models.Page).filter(models.Page.id == created["id"]).one()
        )
        self.assertNotEqual(refreshed.updated_at, sentinel)
        self.assertGreater(refreshed.updated_at, sentinel)

    # ── attach_page ──────────────────────────────────────────────────────

    def test_attach_page_missing_slug_returns_404(self):
        created = self._create_page().json()
        res = self.client.post(
            "/admin/pages/attach", json={"page_id": created["id"], "slug": "page-doesnotexist"}
        )
        self.assertEqual(res.status_code, 404)

    def test_attach_page_rejects_non_page_content_type(self):
        created = self._create_page().json()
        self._make_slug("url-abc123", "url")
        res = self.client.post(
            "/admin/pages/attach", json={"page_id": created["id"], "slug": "url-abc123"}
        )
        self.assertEqual(res.status_code, 400)

    def test_attach_page_missing_page_id_returns_404(self):
        self._make_slug("page-abc123", "page")
        res = self.client.post(
            "/admin/pages/attach", json={"page_id": 999999, "slug": "page-abc123"}
        )
        self.assertEqual(res.status_code, 404)

    def test_attach_page_succeeds(self):
        created = self._create_page().json()
        self._make_slug("page-abc123", "page")
        res = self.client.post(
            "/admin/pages/attach", json={"page_id": created["id"], "slug": "page-abc123"}
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json()["success"])

    def test_reattach_deactivates_previous_attachment_and_preserves_history(self):
        page_a = self._create_page(title="Page A").json()
        page_b = self._create_page(title="Page B").json()
        self._make_slug("page-abc123", "page")

        self.client.post(
            "/admin/pages/attach", json={"page_id": page_a["id"], "slug": "page-abc123"}
        )
        self.client.post(
            "/admin/pages/attach", json={"page_id": page_b["id"], "slug": "page-abc123"}
        )

        attachments = (
            self.db.query(models.PageSlugAttachment)
            .filter(models.PageSlugAttachment.slug == "page-abc123")
            .order_by(models.PageSlugAttachment.id)
            .all()
        )
        self.assertEqual(len(attachments), 2)
        self.assertFalse(attachments[0].is_active)
        self.assertEqual(attachments[0].page_id, page_a["id"])
        self.assertTrue(attachments[1].is_active)
        self.assertEqual(attachments[1].page_id, page_b["id"])

    # ── detach_page ──────────────────────────────────────────────────────

    def test_detach_page_no_active_attachment_is_a_safe_noop(self):
        self._make_slug("page-abc123", "page")
        res = self.client.post("/admin/pages/detach", json={"slug": "page-abc123"})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["success"])
        self.assertNotIn("detached_page_id", body)

    def test_detach_page_deactivates_active_attachment(self):
        created = self._create_page().json()
        self._make_slug("page-abc123", "page")
        self.client.post(
            "/admin/pages/attach", json={"page_id": created["id"], "slug": "page-abc123"}
        )
        res = self.client.post("/admin/pages/detach", json={"slug": "page-abc123"})
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["detached_page_id"], created["id"])

        attachment = (
            self.db.query(models.PageSlugAttachment)
            .filter(models.PageSlugAttachment.slug == "page-abc123")
            .first()
        )
        self.assertFalse(attachment.is_active)


if __name__ == "__main__":
    unittest.main()
