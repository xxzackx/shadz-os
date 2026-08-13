"""Tests for UI3D-B: Activation Visibility (read-only).

GET /admin/links/search now embeds Activation Engine v1 state in each
url/media LinkSearchResult via a new `activation` field (ActivationInfo |
None). This is strictly a read-model addition: search_links() never
creates/backfills an ActivationRecord — a missing record for a url/media
slug means "legacy, predates the Activation Engine", not "unactivated",
and must render as such in static/admin.html rather than being conflated.

Covers:
  1. unactivated URL slug with ActivationRecord
  2. activated URL slug with owner
  3. activated Media slug with owner
  4. inactive owner still visible
  5. missing owner (owner_client_id set but no matching BotClient) handled safely
  6. Page slug -> activation is None
  7. legacy URL slug without ActivationRecord -> activation is None
  8. legacy Media slug without ActivationRecord -> activation is None
  9. no read path creates a missing ActivationRecord
  10. phone search and exact-slug search return identical activation data
  11. token presence boolean exposed
  12. raw activation token never exposed
  13. frontend shows "Old Client" for url/media when activation is null
  14. frontend does NOT label a missing ActivationRecord as "Unactivated"
  15. Page cards do not show the Activation panel

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


class ActivationVisibilityTests(unittest.TestCase):
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

    def _count_activation_records(self):
        db = self.SessionLocal()
        try:
            return db.query(models.ActivationRecord).count()
        finally:
            db.close()

    def _make_bot_client(self, client_name, telegram_username=None, is_active=True):
        db = self.SessionLocal()
        try:
            client = models.BotClient(
                client_name=client_name,
                access_code=f"code-{client_name}",
                telegram_username=telegram_username,
                is_active=is_active,
            )
            db.add(client)
            db.commit()
            db.refresh(client)
            return client.id
        finally:
            db.close()

    def _activate(self, slug, owner_client_id):
        """Directly flips an existing ActivationRecord to activated with an
        owner — Activation Engine write logic itself is out of scope for
        UI3D-B, this only sets up fixture state for the read-model test.
        """
        db = self.SessionLocal()
        try:
            ar = db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == slug).first()
            ar.activation_status = "activated"
            ar.owner_client_id = owner_client_id
            from datetime import datetime, timezone
            ar.activated_at = datetime(2026, 8, 1, 12, 0, 0, tzinfo=timezone.utc)
            db.commit()
        finally:
            db.close()

    # ── 1. unactivated URL slug with ActivationRecord ───────────────────────
    def test_unactivated_url_slug_shows_activation_record(self):
        slug = self._create_link("url", "5551001")
        res = self.client.get("/admin/links/search", params={"slug": slug})
        activation = res.json()["results"][0]["activation"]
        self.assertIsNotNone(activation)
        self.assertEqual(activation["activation_status"], "unactivated")
        self.assertIsNone(activation["owner_client_id"])
        self.assertIsNone(activation["activated_at"])
        self.assertTrue(activation["has_activation_token"])

    # ── 2. activated URL slug with owner ────────────────────────────────────
    def test_activated_url_slug_shows_owner(self):
        slug = self._create_link("url", "5551002")
        owner_id = self._make_bot_client("Alice", telegram_username="alice_tg")
        self._activate(slug, owner_id)

        res = self.client.get("/admin/links/search", params={"slug": slug})
        activation = res.json()["results"][0]["activation"]
        self.assertEqual(activation["activation_status"], "activated")
        self.assertEqual(activation["owner_client_id"], owner_id)
        self.assertEqual(activation["owner_client_name"], "Alice")
        self.assertEqual(activation["owner_telegram_username"], "alice_tg")
        self.assertTrue(activation["owner_client_active"])
        self.assertIsNotNone(activation["activated_at"])

    # ── 3. activated Media slug with owner ──────────────────────────────────
    def test_activated_media_slug_shows_owner(self):
        slug = self._create_link("media", "5551003", destination_url="")
        owner_id = self._make_bot_client("Bob")
        self._activate(slug, owner_id)

        res = self.client.get("/admin/links/search", params={"slug": slug})
        activation = res.json()["results"][0]["activation"]
        self.assertEqual(activation["activation_status"], "activated")
        self.assertEqual(activation["owner_client_name"], "Bob")

    # ── 4. inactive owner still visible ─────────────────────────────────────
    def test_inactive_owner_still_reported(self):
        slug = self._create_link("url", "5551004")
        owner_id = self._make_bot_client("Carol", is_active=False)
        self._activate(slug, owner_id)

        res = self.client.get("/admin/links/search", params={"slug": slug})
        activation = res.json()["results"][0]["activation"]
        self.assertEqual(activation["owner_client_name"], "Carol")
        self.assertFalse(activation["owner_client_active"])

    # ── 5. missing owner handled safely ─────────────────────────────────────
    def test_missing_owner_client_handled_safely(self):
        slug = self._create_link("url", "5551005")
        # owner_client_id points at a BotClient id that doesn't exist.
        db = self.SessionLocal()
        try:
            ar = db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == slug).first()
            ar.activation_status = "activated"
            ar.owner_client_id = 999999
            db.commit()
        finally:
            db.close()

        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertEqual(res.status_code, 200)
        activation = res.json()["results"][0]["activation"]
        self.assertEqual(activation["owner_client_id"], 999999)
        self.assertIsNone(activation["owner_client_name"])
        self.assertIsNone(activation["owner_telegram_username"])
        self.assertIsNone(activation["owner_client_active"])

    # ── 6. Page slug -> activation is None ──────────────────────────────────
    def test_page_slug_activation_is_none(self):
        slug = self._create_link("page", "5551006", destination_url="")
        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertIsNone(res.json()["results"][0]["activation"])

    # ── 7/8. legacy URL/Media slug without ActivationRecord -> None ────────
    def _make_legacy_link(self, content_type, phone):
        """Simulates a pre-Activation-Engine row: a RedirectLink with no
        ActivationRecord, inserted directly (bypassing create_link, which
        always provisions one for url/media).
        """
        db = self.SessionLocal()
        try:
            link = models.RedirectLink(
                slug=f"{content_type}-legacy{phone[-4:]}",
                destination_url="https://example.com/legacy",
                content_type=content_type,
                phone_number=phone,
            )
            db.add(link)
            db.commit()
            return link.slug
        finally:
            db.close()

    def test_legacy_url_slug_without_activation_record_is_none(self):
        slug = self._make_legacy_link("url", "5551007")
        res = self.client.get("/admin/links/search", params={"slug": slug})
        results = res.json()["results"]
        self.assertEqual(len(results), 1)
        self.assertIsNone(results[0]["activation"])

    def test_legacy_media_slug_without_activation_record_is_none(self):
        slug = self._make_legacy_link("media", "5551008")
        res = self.client.get("/admin/links/search", params={"slug": slug})
        results = res.json()["results"]
        self.assertEqual(len(results), 1)
        self.assertIsNone(results[0]["activation"])

    # ── 9. no read path creates a missing ActivationRecord ─────────────────
    def test_search_read_path_never_creates_activation_record(self):
        slug = self._make_legacy_link("url", "5551009")
        before = self._count_activation_records()

        self.client.get("/admin/links/search", params={"slug": slug})
        self.client.get("/admin/links/search", params={"phone_number": "5551009"})

        after = self._count_activation_records()
        self.assertEqual(before, after)
        # And the legacy slug still has none of its own.
        db = self.SessionLocal()
        try:
            self.assertIsNone(
                db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == slug).first()
            )
        finally:
            db.close()

    # ── 10. phone search and exact-slug search return identical data ───────
    def test_phone_search_and_exact_slug_search_match(self):
        slug = self._create_link("url", "5551010")
        owner_id = self._make_bot_client("Dana")
        self._activate(slug, owner_id)

        by_slug = self.client.get("/admin/links/search", params={"slug": slug}).json()["results"][0]
        by_phone = self.client.get(
            "/admin/links/search", params={"phone_number": "5551010"}
        ).json()["results"][0]
        self.assertEqual(by_slug["activation"], by_phone["activation"])

    # ── 11. token presence boolean exposed ──────────────────────────────────
    def test_has_activation_token_is_true_when_record_exists(self):
        slug = self._create_link("url", "5551011")
        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertIs(res.json()["results"][0]["activation"]["has_activation_token"], True)

    # ── 12. raw activation token never exposed ──────────────────────────────
    def test_raw_activation_token_never_in_response(self):
        slug = self._create_link("url", "5551012")
        db = self.SessionLocal()
        try:
            ar = db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == slug).first()
            token = ar.activation_token
        finally:
            db.close()

        res = self.client.get("/admin/links/search", params={"slug": slug})
        body_text = res.text
        self.assertNotIn(token, body_text)
        self.assertNotIn("activation_token", res.json()["results"][0]["activation"])


ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminHtmlActivationPanelTests(unittest.TestCase):
    """static/admin.html is a single-file, no-build-step template — read the
    file directly and assert on structural markers, matching the existing
    lightweight test style for this file.
    """

    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    def _build_result_card_body(self):
        match = re.search(
            r"function buildResultCard\(r, index\) \{.*?\n    \}\n", self.html, re.DOTALL
        )
        self.assertIsNotNone(match, "buildResultCard() not found")
        return match.group(0)

    # ── 13. frontend shows "Old Client" ─────────────────────────────────────
    def test_legacy_activation_label_present(self):
        body = self._build_result_card_body()
        self.assertIn("Old Client", body)
        self.assertNotIn("Legacy / Activation Not Required", body)

    # ── 14. frontend does NOT label missing ActivationRecord as "Unactivated" ─
    def test_missing_activation_record_never_labeled_unactivated(self):
        body = self._build_result_card_body()
        # The only "Unactivated" text allowed is the literal DB status string
        # rendered from a.activation_status (i.e. r.activation truthy) — the
        # else-branch (missing record) must not contain that literal string.
        else_branch_match = re.search(
            r"// No ActivationRecord and no BotClient assignment.*?\n(.*?)</div>`;",
            body, re.DOTALL,
        )
        self.assertIsNotNone(else_branch_match, "legacy/no-record branch not found")
        self.assertNotIn("Unactivated", else_branch_match.group(1))

    # ── 15. Page cards do not show the Activation panel ────────────────────
    def test_page_slugs_excluded_from_activation_panel(self):
        body = self._build_result_card_body()
        gate_match = re.search(
            r"let activationHtml = '';\s*\n\s*if \((.*?)\) \{", body
        )
        self.assertIsNotNone(gate_match, "activationHtml gating condition not found")
        condition = gate_match.group(1)
        self.assertNotIn("page", condition)
        self.assertIn("'url'", condition)
        self.assertIn("'media'", condition)


if __name__ == "__main__":
    unittest.main()
