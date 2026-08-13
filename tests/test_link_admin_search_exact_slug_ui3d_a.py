"""Tests for UI3D-A direct-slug-lookup parity fix.

Admin's direct slug lookup previously called GET /admin/link/{slug}, whose
response model (LinkInfo) lacks is_archived, active_media, and nfc_url — the
fields static/admin.html's buildResultCard() needs for full card parity with
phone search. Fix: GET /admin/links/search now accepts an optional exact
`slug` query param (in addition to the existing `phone_number` partial
match), reusing the same LinkSearchResult enrichment loop unchanged.

Covers:
  - exact URL slug search returns full LinkSearchResult shape
  - exact archived slug is still found when include_archived=true
  - exact Media slug search embeds active_media
  - exact Page slug search returns the same shape as url/media
  - existing phone_number search behavior is unchanged
  - neither phone_number nor slug supplied -> 400 (not 422/500)

Uses a dedicated FastAPI app with an isolated in-memory SQLite database —
never touches the real shadz.db.
"""
import os
import re
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


class ExactSlugSearchTests(unittest.TestCase):
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

    # ── 1. exact URL slug search ────────────────────────────────────────────
    def test_exact_url_slug_search_returns_full_card_shape(self):
        create_res = self.client.post(
            "/admin/link",
            json={
                "content_type": "url",
                "destination_url": "https://example.com/a",
                "phone_number": "5550001",
            },
        )
        self.assertEqual(create_res.status_code, 201)
        slug = create_res.json()["slug"]

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertEqual(res.status_code, 200)
        results = res.json()["results"]
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["slug"], slug)
        self.assertEqual(r["nfc_url"], f"https://shadz.io/{slug}")
        self.assertIs(r["is_archived"], False)
        self.assertIsNone(r["active_media"])

    # ── 2. exact archived slug ──────────────────────────────────────────────
    def test_exact_archived_slug_found_with_include_archived(self):
        create_res = self.client.post(
            "/admin/link",
            json={
                "content_type": "url",
                "destination_url": "https://example.com/b",
                "phone_number": "5550002",
            },
        )
        slug = create_res.json()["slug"]
        archive_res = self.client.post(f"/admin/link/{slug}/archive")
        self.assertEqual(archive_res.status_code, 200)

        # Without include_archived, an archived slug must not be returned —
        # same default-active-only behavior as phone search.
        res_default = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertEqual(res_default.json()["results"], [])

        res = self.client.get(
            "/admin/links/search", params={"slug": slug, "include_archived": "true"}
        )
        self.assertEqual(res.status_code, 200)
        results = res.json()["results"]
        self.assertEqual(len(results), 1)
        self.assertIs(results[0]["is_archived"], True)

    # ── 3. exact Media slug with active_media ───────────────────────────────
    def test_exact_media_slug_embeds_active_media(self):
        create_res = self.client.post(
            "/admin/link",
            json={"content_type": "media", "phone_number": "5550003"},
        )
        slug = create_res.json()["slug"]

        db = self.SessionLocal()
        try:
            asset = models.MediaAsset(
                media_type="image",
                storage_key="k1",
                public_url="https://media.shadz.io/k1.jpg",
                original_filename="hero.jpg",
                mime_type="image/jpeg",
                file_size=1234,
            )
            db.add(asset)
            db.flush()
            db.add(models.SlugMedia(slug=slug, media_asset_id=asset.id, is_active=True))
            db.commit()
        finally:
            db.close()

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertEqual(res.status_code, 200)
        results = res.json()["results"]
        self.assertEqual(len(results), 1)
        active_media = results[0]["active_media"]
        self.assertIsNotNone(active_media)
        self.assertEqual(active_media["original_filename"], "hero.jpg")
        self.assertEqual(active_media["media_type"], "image")

    # ── 4. exact Page slug ───────────────────────────────────────────────────
    def test_exact_page_slug_returns_same_shape_as_url_and_media(self):
        create_res = self.client.post(
            "/admin/link",
            json={
                "content_type": "page",
                "destination_url": "",
                "phone_number": "5550004",
            },
        )
        self.assertEqual(create_res.status_code, 201)
        slug = create_res.json()["slug"]

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertEqual(res.status_code, 200)
        results = res.json()["results"]
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r["content_type"], "page")
        self.assertIs(r["is_archived"], False)
        self.assertIn("nfc_url", r)

    # ── 5. existing phone search unchanged ──────────────────────────────────
    def test_phone_number_search_unchanged(self):
        create_res = self.client.post(
            "/admin/link",
            json={
                "content_type": "url",
                "destination_url": "https://example.com/c",
                "phone_number": "5559876",
            },
        )
        self.assertEqual(create_res.status_code, 201)

        res = self.client.get("/admin/links/search", params={"phone_number": "5559876"})
        self.assertEqual(res.status_code, 200)
        results = res.json()["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["phone_number"], "5559876")

    # ── 6. neither parameter supplied -> safe 4xx ──────────────────────────
    def test_no_phone_number_or_slug_returns_400(self):
        res = self.client.get("/admin/links/search")
        self.assertEqual(res.status_code, 400)
        self.assertIn("phone_number", res.json()["detail"])


ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminHtmlLookupEndpointTests(unittest.TestCase):
    """static/admin.html is a single-file, no-build-step template — read the
    file directly and assert on which endpoint each function calls, matching
    the existing lightweight test style for this file.
    """

    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    # ── 7. frontend direct lookup uses /admin/links/search?slug=... ────────
    def test_lookup_slug_direct_uses_links_search_with_slug_param(self):
        match = re.search(
            r"async function lookupSlugDirect\(\).*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(match, "lookupSlugDirect() not found")
        body = match.group(0)
        self.assertIn("/admin/links/search?slug=", body)
        self.assertIn("include_archived=true", body)
        self.assertNotIn("/admin/link/${encodeURIComponent(slug)}`", body)

    # ── 8. Update Redirect still uses GET /admin/link/{slug} ───────────────
    def test_load_update_preview_still_uses_get_link_by_slug(self):
        match = re.search(
            r"async function loadUpdatePreview\(\).*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(match, "loadUpdatePreview() not found")
        body = match.group(0)
        self.assertIn("`/admin/link/${encodeURIComponent(slug)}`", body)
        self.assertNotIn("/admin/links/search", body)


if __name__ == "__main__":
    unittest.main()
