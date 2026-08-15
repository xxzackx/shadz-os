"""Tests for UI3D-C2: Page Slug Detail.

GET /admin/links/search now embeds the active Page attachment's identity in
each page LinkSearchResult via a new `page_attachment` field
(PageAttachmentInfo | None), exposing page_id and template_type so the Admin
UI can identify the attached Page without a separate call. Strictly a
read-model addition: search_links() never creates/backfills a
PageSlugAttachment.

Covers:
  1. page slug with an active PageSlugAttachment -> page_attachment populated
     with correct page_id and template_type
  2. page slug with no PageSlugAttachment -> page_attachment is None
  3. page slug with an inactive (history) PageSlugAttachment only -> page_attachment is None
  4. url slug -> page_attachment is None (never populated for non-page types)
  5. media slug -> page_attachment is None
  6. phone search and exact-slug search return identical page_attachment data

Uses a dedicated FastAPI app with an isolated in-memory SQLite database —
never touches the real shadz.db.
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
from link_admin import register_link_admin_routes


class PageAttachmentDetailTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)

        app = FastAPI()
        router = APIRouter(prefix="/admin")
        register_link_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

    def _create_link(self, content_type, phone, destination_url="https://example.com"):
        res = self.client.post(
            "/admin/link",
            json={
                "content_type": content_type,
                "destination_url": destination_url,
                "phone_number": phone,
            },
        )
        self.assertEqual(res.status_code, 201)
        return res.json()["slug"]

    def _make_page(self, title="Wedding", template_type="invitation"):
        db = self.SessionLocal()
        try:
            page = models.Page(title=title, template_type=template_type)
            db.add(page)
            db.commit()
            db.refresh(page)
            return page.id
        finally:
            db.close()

    def _attach_page(self, page_id, slug, is_active=True):
        db = self.SessionLocal()
        try:
            attachment = models.PageSlugAttachment(page_id=page_id, slug=slug, is_active=is_active)
            db.add(attachment)
            db.commit()
        finally:
            db.close()

    # ── 1. page slug with active attachment ─────────────────────────────────
    def test_page_slug_with_active_attachment_shows_page_id_and_type(self):
        slug = self._create_link("page", "5552001", destination_url="")
        page_id = self._make_page(title="Wedding Invite", template_type="invitation")
        self._attach_page(page_id, slug)

        res = self.client.get("/admin/links/search", params={"slug": slug})
        page_attachment = res.json()["results"][0]["page_attachment"]
        self.assertIsNotNone(page_attachment)
        self.assertEqual(page_attachment["page_id"], page_id)
        self.assertEqual(page_attachment["template_type"], "invitation")

    # ── 2. page slug with no attachment ─────────────────────────────────────
    def test_page_slug_without_attachment_is_none(self):
        slug = self._create_link("page", "5552002", destination_url="")

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertIsNone(res.json()["results"][0]["page_attachment"])

    # ── 3. page slug with only an inactive (history) attachment ────────────
    def test_page_slug_with_only_inactive_attachment_is_none(self):
        slug = self._create_link("page", "5552003", destination_url="")
        page_id = self._make_page()
        self._attach_page(page_id, slug, is_active=False)

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertIsNone(res.json()["results"][0]["page_attachment"])

    # ── 4. url slug never gets page_attachment ──────────────────────────────
    def test_url_slug_page_attachment_is_none(self):
        slug = self._create_link("url", "5552004")

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertIsNone(res.json()["results"][0]["page_attachment"])

    # ── 5. media slug never gets page_attachment ────────────────────────────
    def test_media_slug_page_attachment_is_none(self):
        slug = self._create_link("media", "5552005", destination_url="")

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertIsNone(res.json()["results"][0]["page_attachment"])

    # ── 6. phone search and exact-slug search parity ────────────────────────
    def test_phone_search_and_exact_slug_search_return_identical_page_attachment(self):
        slug = self._create_link("page", "5552006", destination_url="")
        page_id = self._make_page(title="Product Launch", template_type="brand_product")
        self._attach_page(page_id, slug)

        by_phone = self.client.get(
            "/admin/links/search", params={"phone_number": "5552006"}
        ).json()["results"][0]["page_attachment"]
        by_slug = self.client.get(
            "/admin/links/search", params={"slug": slug}
        ).json()["results"][0]["page_attachment"]

        self.assertEqual(by_phone, by_slug)
        self.assertEqual(by_phone["page_id"], page_id)
        self.assertEqual(by_phone["template_type"], "brand_product")


if __name__ == "__main__":
    unittest.main()
