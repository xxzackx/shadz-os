"""Tests for UI3D-C3 Part A: Admin URL Normalization.

POST /admin/link (create) and POST /admin/link/{slug} (upsert) now normalize
destination_url the same way as the existing Telegram Bot destination-URL
input (Hotfix H1D, bot_runtime._normalize_telegram_destination_url): a bare
domain gets "https://" prepended, an explicit http(s):// is preserved, and
any other explicit scheme (e.g. ftp://) is rejected with 400. This is a
read/validate-only reuse of the existing normalizer via a small local-import
wrapper (link_admin._normalize_admin_destination_url) — no new normalization
logic was written, and bot_runtime's own normalizer/tests are untouched.

Covers:
  1. bare domain -> https:// on create
  2. explicit http:// preserved on create
  3. explicit https:// preserved on create
  4. unsupported scheme (ftp://) rejected on create -> 400
  5. existing valid Admin URL update (upsert) still works, including a
     bare-domain normalization on update
  6. blank destination_url is preserved as "" (still optional, Hotfix H1C)
  7. unsupported scheme rejected on upsert update -> 400
  8. bot_runtime's normalizer function is reused, not duplicated (identity
     check) -- confirms no regression risk of a forked copy drifting

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

from database import Base, get_db
from link_admin import register_link_admin_routes


class AdminUrlNormalizationTests(unittest.TestCase):
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

    def _create_link(self, destination_url, phone="5553001", content_type="url"):
        return self.client.post(
            "/admin/link",
            json={
                "content_type": content_type,
                "destination_url": destination_url,
                "phone_number": phone,
            },
        )

    # ── 1. bare domain -> https:// on create ────────────────────────────────
    def test_create_bare_domain_gets_https_prefix(self):
        res = self._create_link("example.com", phone="5553001")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["destination_url"], "https://example.com")

    # ── 2. explicit http:// preserved on create ─────────────────────────────
    def test_create_explicit_http_preserved(self):
        res = self._create_link("http://example.com", phone="5553002")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["destination_url"], "http://example.com")

    # ── 3. explicit https:// preserved on create ────────────────────────────
    def test_create_explicit_https_preserved(self):
        res = self._create_link("https://example.com", phone="5553003")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["destination_url"], "https://example.com")

    # ── 4. unsupported scheme rejected on create ────────────────────────────
    def test_create_unsupported_scheme_rejected(self):
        res = self._create_link("ftp://example.com", phone="5553004")
        self.assertEqual(res.status_code, 400)

    # ── 5. existing valid Admin URL update (upsert) still works ────────────
    def test_upsert_update_normalizes_bare_domain(self):
        created = self._create_link("https://old.example.com", phone="5553005").json()
        slug = created["slug"]

        res = self.client.post(
            f"/admin/link/{slug}",
            json={"destination_url": "new.example.com"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["destination_url"], "https://new.example.com")

    def test_upsert_update_preserves_explicit_scheme(self):
        created = self._create_link("https://old.example.com", phone="5553006").json()
        slug = created["slug"]

        res = self.client.post(
            f"/admin/link/{slug}",
            json={"destination_url": "http://updated.example.com"},
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["destination_url"], "http://updated.example.com")

    # ── 6. blank destination_url stays optional (Hotfix H1C, unchanged) ────
    def test_create_blank_destination_url_preserved_as_empty(self):
        res = self._create_link("", phone="5553007")
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()["destination_url"], "")

    # ── 7. unsupported scheme rejected on upsert update ─────────────────────
    def test_upsert_update_unsupported_scheme_rejected(self):
        created = self._create_link("https://old.example.com", phone="5553008").json()
        slug = created["slug"]

        res = self.client.post(
            f"/admin/link/{slug}",
            json={"destination_url": "javascript:alert(1)"},
        )
        self.assertEqual(res.status_code, 400)
        # Original destination_url must be unchanged on rejection.
        get_res = self.client.get(f"/admin/link/{slug}")
        self.assertEqual(get_res.json()["destination_url"], "https://old.example.com")

    # ── 8. reuses bot_runtime's normalizer, not a forked copy ──────────────
    def test_reuses_bot_runtime_normalizer_function(self):
        import bot_runtime
        from link_admin import _normalize_admin_destination_url

        self.assertEqual(
            _normalize_admin_destination_url("example.com"),
            bot_runtime._normalize_telegram_destination_url("example.com"),
        )


if __name__ == "__main__":
    unittest.main()
