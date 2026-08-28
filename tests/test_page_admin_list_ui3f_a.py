"""Regression tests for GET /admin/pages — the read-only Page browse list
added in Admin Panel UI v0.3 Phase UI3F-A.

Same isolation approach as tests/test_page_admin.py: a minimal FastAPI app
registering only the Page Engine admin routes, with get_db overridden to a
per-test in-memory SQLite database. Nothing here imports main.py or touches
the real shadz.db. No Basic Auth is applied (verify_admin lives in main.py
and is exercised separately); these tests are scoped to page_admin.py logic.
"""
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


class PageListEndpointTests(unittest.TestCase):
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

    # ── helpers ──────────────────────────────────────────────────────────

    def _make_slug(self, slug, content_type="page"):
        link = models.RedirectLink(
            slug=slug, destination_url="", content_type=content_type
        )
        self.db.add(link)
        self.db.commit()
        return link

    def _create_page(self, **overrides):
        payload = {"title": "Test Page", "template_type": "invitation"}
        payload.update(overrides)
        res = self.client.post("/admin/pages", json=payload)
        self.assertEqual(res.status_code, 201, res.text)
        return res.json()

    def _attach(self, page_id, slug):
        res = self.client.post(
            "/admin/pages/attach", json={"page_id": page_id, "slug": slug}
        )
        self.assertEqual(res.status_code, 200, res.text)

    def _detach(self, slug):
        res = self.client.post("/admin/pages/detach", json={"slug": slug})
        self.assertEqual(res.status_code, 200, res.text)

    # ── list behaviour ──────────────────────────────────────────────────

    def test_empty_list_when_no_pages(self):
        res = self.client.get("/admin/pages")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), [])

    def test_page_with_no_attachment_is_included_with_empty_slugs(self):
        page = self._create_page(title="Lonely")

        res = self.client.get("/admin/pages")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(len(body), 1)
        item = body[0]
        self.assertEqual(item["id"], page["id"])
        self.assertEqual(item["title"], "Lonely")
        self.assertEqual(item["template_type"], "invitation")
        self.assertEqual(item["status"], "draft")
        self.assertEqual(item["active_slugs"], [])
        # a page created with no content_json reports it as null
        self.assertIsNone(item["content_json"])
        # exact field set — no leakage of archived_at / storage columns etc.
        self.assertEqual(
            set(item.keys()),
            {"id", "title", "template_type", "status", "content_json",
             "created_at", "updated_at", "active_slugs"},
        )

    def test_list_returns_raw_content_json_unchanged(self):
        # UI3F-B prefill needs the page's current raw content_json so the
        # existing Edit Page form can be populated without a second request.
        raw = '{"message": "Hi <there> & \\"friends\\"", "n": 3}'
        with_content = self._create_page(title="Has Content", content_json=raw)
        without_content = self._create_page(title="No Content")

        by_id = {p["id"]: p for p in self.client.get("/admin/pages").json()}
        # byte-for-byte the same string that was stored — not parsed/reshaped
        self.assertEqual(by_id[with_content["id"]]["content_json"], raw)
        self.assertIsNone(by_id[without_content["id"]]["content_json"])
        # still no unrelated columns leaked alongside the new field
        self.assertEqual(
            set(by_id[with_content["id"]].keys()),
            {"id", "title", "template_type", "status", "content_json",
             "created_at", "updated_at", "active_slugs"},
        )

    def test_page_with_one_active_attachment(self):
        page = self._create_page()
        self._make_slug("page-one")
        self._attach(page["id"], "page-one")

        item = self.client.get("/admin/pages").json()[0]
        self.assertEqual(item["active_slugs"], ["page-one"])

    def test_page_with_multiple_active_attachments_sorted_by_slug(self):
        page = self._create_page()
        for slug in ("page-c", "page-a", "page-b"):
            self._make_slug(slug)
            self._attach(page["id"], slug)

        item = self.client.get("/admin/pages").json()[0]
        # one page, many active slugs, deterministic slug-ascending order
        self.assertEqual(item["active_slugs"], ["page-a", "page-b", "page-c"])

    def test_inactive_attachment_is_excluded(self):
        page_a = self._create_page(title="Page A")
        page_b = self._create_page(title="Page B")
        self._make_slug("page-shared")

        # attach A, then re-attach B -> A's attachment row goes is_active=False
        self._attach(page_a["id"], "page-shared")
        self._attach(page_b["id"], "page-shared")

        by_id = {p["id"]: p for p in self.client.get("/admin/pages").json()}
        self.assertEqual(by_id[page_a["id"]]["active_slugs"], [])
        self.assertEqual(by_id[page_b["id"]]["active_slugs"], ["page-shared"])

        # an explicit detach also drops the slug from the list
        self._detach("page-shared")
        by_id = {p["id"]: p for p in self.client.get("/admin/pages").json()}
        self.assertEqual(by_id[page_b["id"]]["active_slugs"], [])

    def test_deterministic_ordering_newest_id_first(self):
        first = self._create_page(title="First")
        second = self._create_page(title="Second")
        third = self._create_page(title="Third")

        ids = [p["id"] for p in self.client.get("/admin/pages").json()]
        self.assertEqual(ids, [third["id"], second["id"], first["id"]])
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_list_is_read_only_no_page_or_attachment_rows_created(self):
        page = self._create_page()
        self._make_slug("page-ro")
        self._attach(page["id"], "page-ro")

        before_pages = self.db.query(models.Page).count()
        before_att = self.db.query(models.PageSlugAttachment).count()

        for _ in range(3):
            self.assertEqual(self.client.get("/admin/pages").status_code, 200)

        self.assertEqual(self.db.query(models.Page).count(), before_pages)
        self.assertEqual(
            self.db.query(models.PageSlugAttachment).count(), before_att
        )


if __name__ == "__main__":
    unittest.main()
