"""Regression tests for Activation Engine v1 — Production Hotfix H1C
(URL slug creation without required destination).

Covers both slug-creation paths in link_admin.py:
  - POST /admin/link        (create_link — auto-generated slug)
  - POST /admin/link/{slug} (upsert_link — new-slug branch)

Before H1C, both paths rejected a "url" content_type slug (and, for the
upsert path, any new slug) with a 400 if destination_url was blank/omitted.
H1C removes that requirement so an Admin can create a URL slug and populate
its destination later (via Admin Change Destination or the Activation
Engine), matching how H1A's Unassign flow already leaves destination_url
as "" (see tests/test_activation_engine_h1a.py).

The public redirect guard that makes an empty destination_url safe already
exists, unchanged, at main.py's redirect_slug (`if not link.destination_url:
raise HTTPException(404)`) — the exact same falsy-string check already
exercised by the H1A regression suite for the Unassign case. This file does
not re-import main.py (no test in this suite does, to avoid touching the
real shadz.db at module import time); instead it verifies the precondition
that guard relies on: a slug created without a destination stores
destination_url as "" (falsy), never None or a malformed value.

Uses a dedicated FastAPI app registering only the Link Engine admin routes,
with get_db overridden to an isolated in-memory SQLite database (matching
tests/test_link_admin_activation.py's pattern) — never touches the real
shadz.db.
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


class UrlSlugCreationWithoutDestinationTests(unittest.TestCase):
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
        register_link_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app, raise_server_exceptions=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _link(self, slug):
        return (
            self.db.query(models.RedirectLink)
            .filter(models.RedirectLink.slug == slug)
            .first()
        )

    def _activation_record_for(self, slug):
        return (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == slug)
            .first()
        )

    # ── POST /admin/link (auto-generated slug) ──────────────────────────────

    def test_create_url_slug_with_omitted_destination_succeeds(self):
        response = self.client.post(
            "/admin/link",
            json={"content_type": "url", "phone_number": "555-0200"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["destination_url"], "")

        link = self._link(response.json()["slug"])
        self.assertEqual(link.destination_url, "")
        self.assertIsNotNone(link.destination_url)  # never NULL — falsy "" only

    def test_create_url_slug_with_blank_destination_succeeds(self):
        response = self.client.post(
            "/admin/link",
            json={"content_type": "url", "destination_url": "", "phone_number": "555-0201"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["destination_url"], "")

    def test_create_url_slug_with_valid_destination_still_succeeds(self):
        response = self.client.post(
            "/admin/link",
            json={
                "content_type": "url",
                "destination_url": "https://example.com/promo",
                "phone_number": "555-0202",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()["destination_url"], "https://example.com/promo")

    def test_blank_destination_slug_activation_record_still_created(self):
        # Requirement: an activation-enabled unactivated url slug with blank
        # destination must still enter the existing Activation Engine flow.
        response = self.client.post(
            "/admin/link",
            json={"content_type": "url", "phone_number": "555-0203"},
        )
        self.assertEqual(response.status_code, 201, response.text)
        slug = response.json()["slug"]

        record = self._activation_record_for(slug)
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "unactivated")

    def test_blank_destination_is_falsy_not_none_and_not_malformed(self):
        # This is the exact precondition main.py's redirect_slug relies on
        # (`if not link.destination_url: raise HTTPException(404)`), unchanged
        # by H1C, to fail safely instead of a 500 or an empty-string redirect.
        response = self.client.post(
            "/admin/link",
            json={"content_type": "url", "phone_number": "555-0204"},
        )
        link = self._link(response.json()["slug"])
        self.assertFalse(bool(link.destination_url))
        self.assertIsInstance(link.destination_url, str)

    # ── POST /admin/link/{slug} (upsert — new-slug branch) ──────────────────

    def test_upsert_new_url_slug_with_omitted_destination_succeeds(self):
        response = self.client.post(
            "/admin/link/url-nodest",
            json={"content_type": "url", "phone_number": "555-0205"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["destination_url"], "")

        record = self._activation_record_for("url-nodest")
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "unactivated")

    def test_upsert_new_url_slug_with_valid_destination_still_succeeds(self):
        response = self.client.post(
            "/admin/link/url-hasdst",
            json={"destination_url": "https://example.com/x", "phone_number": "555-0206"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["destination_url"], "https://example.com/x")

    def test_upsert_new_url_slug_with_blank_destination_succeeds(self):
        # Explicit "" (as opposed to omitted) — content_type inferred from
        # the slug prefix, no content_type key sent at all.
        response = self.client.post(
            "/admin/link/url-blnkds",
            json={"destination_url": "", "phone_number": "555-0210"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["destination_url"], "")

    def test_upsert_new_media_slug_with_blank_destination_still_fails(self):
        # H1C scope is url-only — new media/page slugs via upsert_link must
        # keep the exact pre-H1C requirement.
        response = self.client.post(
            "/admin/link/media-blnkds",
            json={"destination_url": "", "phone_number": "555-0211"},
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("destination_url is required", response.json()["detail"])
        self.assertIsNone(self._link("media-blnkds"))

    def test_upsert_new_media_slug_with_omitted_destination_still_fails(self):
        response = self.client.post(
            "/admin/link/media-omitds",
            json={"phone_number": "555-0212"},
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("destination_url is required", response.json()["detail"])
        self.assertIsNone(self._link("media-omitds"))

    def test_upsert_new_page_slug_with_blank_destination_still_fails(self):
        response = self.client.post(
            "/admin/link/page-blnkds",
            json={"destination_url": "", "phone_number": "555-0213"},
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("destination_url is required", response.json()["detail"])
        self.assertIsNone(self._link("page-blnkds"))

    def test_upsert_new_page_slug_with_omitted_destination_still_fails(self):
        response = self.client.post(
            "/admin/link/page-omitds",
            json={"phone_number": "555-0214"},
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("destination_url is required", response.json()["detail"])
        self.assertIsNone(self._link("page-omitds"))

    # ── Existing "Change Destination" behaviour must remain unchanged ───────

    def test_change_destination_on_existing_slug_still_works(self):
        create = self.client.post(
            "/admin/link/url-chnged",
            json={"destination_url": "https://example.com/old", "phone_number": "555-0207"},
        )
        self.assertEqual(create.status_code, 200, create.text)

        update = self.client.post(
            "/admin/link/url-chnged",
            json={"destination_url": "https://example.com/new"},
        )
        self.assertEqual(update.status_code, 200, update.text)
        self.assertEqual(update.json()["destination_url"], "https://example.com/new")

    def test_change_destination_rejects_blank_on_existing_slug_via_omission(self):
        # Omitting destination_url on an update must preserve the existing
        # value (LinkUpdate semantics), not clear it — unchanged by H1C.
        self.client.post(
            "/admin/link/url-presrv",
            json={"destination_url": "https://example.com/keep", "phone_number": "555-0208"},
        )
        update = self.client.post(
            "/admin/link/url-presrv",
            json={"client_name": "Renamed Client"},
        )
        self.assertEqual(update.status_code, 200, update.text)
        self.assertEqual(update.json()["destination_url"], "https://example.com/keep")

    # ── H1A regression: Unassign-cleared destination remains valid state ───

    def test_h1a_unassign_style_blank_destination_link_is_readable(self):
        # Mirrors the state left behind by bot_admin's Unassign flow (H1A):
        # destination_url == "" on an otherwise-normal url slug. Confirms
        # GET /admin/link/{slug} still returns it safely (no 500).
        self.client.post(
            "/admin/link/url-wasuna",
            json={"destination_url": "https://example.com/gone", "phone_number": "555-0209"},
        )
        link = self._link("url-wasuna")
        self.assertIsNotNone(link)
        link.destination_url = ""
        self.db.commit()

        response = self.client.get("/admin/link/url-wasuna")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["destination_url"], "")


if __name__ == "__main__":
    unittest.main()
