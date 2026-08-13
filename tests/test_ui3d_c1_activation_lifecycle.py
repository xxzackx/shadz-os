"""Tests for UI3D-C1: Assigned Client Activation Lifecycle.

Covers the reconciliation helper (bot_runtime._reconcile_assigned_slug_
activation), its wiring into the access-code login path, the Admin
read-model additions in link_admin.search_links() (assigned_client), and
the resulting lifecycle-state derivation in static/admin.html's
buildResultCard().

Uses isolated in-memory SQLite databases — never touches the real shadz.db.
No network calls: bot_runtime._send_message is patched with AsyncMock.
"""
import asyncio
import os
import re
import sys
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import bot_runtime
import models
from database import Base, get_db
from link_admin import register_link_admin_routes


def _make_in_memory_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal(), engine


# ---------------------------------------------------------------------------
# Part 1 — direct unit tests of _reconcile_assigned_slug_activation
# ---------------------------------------------------------------------------

class ReconcileHelperTests(unittest.TestCase):
    def setUp(self):
        self.db, self.engine = _make_in_memory_session()

    def tearDown(self):
        self.db.close()

    _client_seq = 0

    def _make_client(self, telegram_user_id=None, telegram_username=None, is_active=True):
        ReconcileHelperTests._client_seq += 1
        client = models.BotClient(
            client_name="Alice",
            access_code=f"CODE{ReconcileHelperTests._client_seq}",
            telegram_user_id=telegram_user_id,
            telegram_username=telegram_username,
            is_active=is_active,
        )
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)
        return client

    def _make_link(self, slug, content_type="url", is_archived=False):
        link = models.RedirectLink(
            slug=slug, destination_url="https://original.example.com",
            content_type=content_type, is_archived=is_archived,
        )
        self.db.add(link)
        self.db.commit()
        return link

    def _assign(self, client, slug):
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug=slug))
        self.db.commit()

    def _get_record(self, slug):
        return self.db.query(models.ActivationRecord).filter(
            models.ActivationRecord.slug == slug
        ).first()

    # ── 6/7/8. legacy no-record slug -> created and committed directly activated ──
    def test_legacy_no_record_slug_created_directly_activated(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("url-legacy1")
        self._assign(client, "url-legacy1")

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        record = self._get_record("url-legacy1")
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)
        self.assertIsNotNone(record.activated_at)
        self.assertTrue(record.activation_token)  # non-empty, freshly generated

    # ── 8. unactivated/no-owner -> activated ────────────────────────────────
    def test_unactivated_no_owner_becomes_activated(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("url-a")
        self._assign(client, "url-a")
        self.db.add(models.ActivationRecord(slug="url-a", activation_token="tok-a"))
        self.db.commit()

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        record = self._get_record("url-a")
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)
        self.assertIsNotNone(record.activated_at)
        self.assertEqual(record.activation_token, "tok-a")  # token preserved

    # ── 9. unactivated/same-owner -> activated ──────────────────────────────
    def test_unactivated_same_owner_becomes_activated(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("url-b")
        self._assign(client, "url-b")
        self.db.add(models.ActivationRecord(
            slug="url-b", activation_token="tok-b", owner_client_id=client.id,
        ))
        self.db.commit()

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        record = self._get_record("url-b")
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)

    # ── 10. activated/same-owner -> no-op ───────────────────────────────────
    def test_activated_same_owner_is_noop(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("url-c")
        self._assign(client, "url-c")
        fixed_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.db.add(models.ActivationRecord(
            slug="url-c", activation_token="tok-c", owner_client_id=client.id,
            activation_status="activated", activated_at=fixed_time,
        ))
        self.db.commit()

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        record = self._get_record("url-c")
        self.assertEqual(record.activated_at.replace(tzinfo=timezone.utc), fixed_time)

    # ── 11. different ActivationRecord owner -> never overwritten ──────────
    def test_different_owner_never_overwritten(self):
        client = self._make_client(telegram_user_id="111")
        other = self._make_client(telegram_user_id="222")
        self._make_link("url-d")
        self._assign(client, "url-d")
        self.db.add(models.ActivationRecord(
            slug="url-d", activation_token="tok-d", owner_client_id=other.id,
            activation_status="activated", activated_at=datetime.now(timezone.utc),
        ))
        self.db.commit()

        with self.assertLogs("bot_runtime", level="WARNING"):
            bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        record = self._get_record("url-d")
        self.assertEqual(record.owner_client_id, other.id)  # untouched

    # ── 12. archived slug skipped ────────────────────────────────────────────
    def test_archived_assigned_slug_skipped(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("url-e", is_archived=True)
        self._assign(client, "url-e")

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        self.assertIsNone(self._get_record("url-e"))

    # ── 13. destination URL unchanged ───────────────────────────────────────
    def test_destination_url_unchanged(self):
        client = self._make_client(telegram_user_id="111")
        link = self._make_link("url-f")
        self._assign(client, "url-f")

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        self.db.refresh(link)
        self.assertEqual(link.destination_url, "https://original.example.com")

    # ── 14. media attachment / SlugMedia unchanged ──────────────────────────
    def test_media_attachment_unchanged(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("media-g", content_type="media")
        self._assign(client, "media-g")
        asset = models.MediaAsset(
            media_type="image", storage_key="k", public_url="https://media.shadz.io/k",
            original_filename="f.jpg", mime_type="image/jpeg", file_size=10,
        )
        self.db.add(asset)
        self.db.flush()
        sm = models.SlugMedia(slug="media-g", media_asset_id=asset.id, is_active=True)
        self.db.add(sm)
        self.db.commit()

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        self.db.refresh(sm)
        self.assertTrue(sm.is_active)
        self.assertEqual(
            self.db.query(models.SlugMedia).filter(models.SlugMedia.slug == "media-g").count(), 1
        )

    # ── 15. one conflicting/failing slug does not prevent siblings ─────────
    def test_one_conflict_does_not_block_sibling_reconciliation(self):
        client = self._make_client(telegram_user_id="111")
        other = self._make_client(telegram_user_id="222")

        self._make_link("url-h1")
        self._assign(client, "url-h1")
        self.db.add(models.ActivationRecord(
            slug="url-h1", activation_token="tok-h1", owner_client_id=other.id,
            activation_status="activated", activated_at=datetime.now(timezone.utc),
        ))
        self._make_link("url-h2")
        self._assign(client, "url-h2")
        self.db.commit()

        with self.assertLogs("bot_runtime", level="WARNING"):
            bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        # Conflicting slug untouched.
        self.assertEqual(self._get_record("url-h1").owner_client_id, other.id)
        # Sibling slug still reconciled successfully.
        r2 = self._get_record("url-h2")
        self.assertEqual(r2.activation_status, "activated")
        self.assertEqual(r2.owner_client_id, client.id)

    # ── A commits, B raises mid-transaction and rolls back, C still commits ──
    def test_genuine_exception_on_middle_slug_rolls_back_only_that_slug(self):
        """A/B/C are all legacy (no ActivationRecord) assigned slugs, so each
        goes through the create-record-then-flip-to-activated path. B's
        creation is forced to raise for real (not a mocked skip/continue —
        an actual exception inside the try block, the smallest stable
        failure injection available: models.create_activation_record_for_slug
        itself raising) to prove the per-slug db.rollback() only discards B's
        own uncommitted work and never touches A's or C's commits, and that
        the client object stays usable across the rollback.
        """
        client = self._make_client(telegram_user_id="111")
        client_id_before = client.id
        for slug in ("url-k1", "url-k2", "url-k3"):
            self._make_link(slug)
            self._assign(client, slug)

        original = models.create_activation_record_for_slug

        def flaky_create(db_, slug, token):
            if slug == "url-k2":
                raise RuntimeError("simulated failure for k2")
            return original(db_, slug, token)

        with patch.object(models, "create_activation_record_for_slug", side_effect=flaky_create):
            with self.assertLogs("bot_runtime", level="ERROR"):
                # Must not raise out of the helper itself.
                bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        rec_a = self._get_record("url-k1")
        rec_b = self._get_record("url-k2")
        rec_c = self._get_record("url-k3")

        self.assertEqual(rec_a.activation_status, "activated")
        self.assertEqual(rec_a.owner_client_id, client.id)

        self.assertIsNone(rec_b, "B's partial work must be fully rolled back — no orphan record")

        self.assertEqual(rec_c.activation_status, "activated")
        self.assertEqual(rec_c.owner_client_id, client.id)

        # BotClient Telegram identity intact; client object still usable
        # (not detached/stale) immediately after the rollback.
        self.assertEqual(client.id, client_id_before)
        self.assertEqual(client.telegram_user_id, "111")

    # ── retryability: no telegram_user_id yet -> no-op ──────────────────────
    def test_no_telegram_user_id_is_noop(self):
        client = self._make_client(telegram_user_id=None)
        self._make_link("url-i")
        self._assign(client, "url-i")

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        self.assertIsNone(self._get_record("url-i"))

    # ── page slugs never processed (defensive — assign_slug already gates) ──
    def test_page_slug_never_processed(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("page-j", content_type="page")
        # Bypass assign_slug's own content_type gate to prove the helper's
        # own defensive check holds even if a page slug were ever assigned.
        self._assign(client, "page-j")

        bot_runtime._reconcile_assigned_slug_activation(client, self.db)

        self.assertIsNone(self._get_record("page-j"))


# ---------------------------------------------------------------------------
# Part 2 — wiring into the access-code login path (_handle_message)
# ---------------------------------------------------------------------------

class LoginTriggerTests(unittest.TestCase):
    def setUp(self):
        self.db, self.engine = _make_in_memory_session()
        bot_runtime._SESSIONS.clear()
        self._send_patcher = patch.object(bot_runtime, "_send_message", new_callable=AsyncMock)
        self.mock_send = self._send_patcher.start()

    def tearDown(self):
        self._send_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    def _make_client(self, access_code="LOGIN1", telegram_user_id=None, is_active=True):
        client = models.BotClient(
            client_name="Bob", access_code=access_code,
            telegram_user_id=telegram_user_id, is_active=is_active,
        )
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)
        return client

    def _make_link(self, slug, content_type="url", is_archived=False):
        self.db.add(models.RedirectLink(
            slug=slug, destination_url="https://x.example.com",
            content_type=content_type, is_archived=is_archived,
        ))
        self.db.commit()

    def _assign(self, client, slug):
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug=slug))
        self.db.commit()

    def _login(self, chat_id, code, telegram_user_id=999, username=None):
        bot_runtime._SESSIONS[chat_id] = {"state": "awaiting_code"}
        asyncio.run(bot_runtime._handle_message(
            chat_id, code, {"id": telegram_user_id, "username": username}, self.db,
            {"text": code},
        ))

    def _record(self, slug):
        return self.db.query(models.ActivationRecord).filter(
            models.ActivationRecord.slug == slug
        ).first()

    # ── 1. first successful login binds identity and reconciles Old Client slug ──
    def test_first_login_binds_identity_and_reconciles(self):
        client = self._make_client()
        self._make_link("url-login1")
        self._assign(client, "url-login1")

        self._login(chat_id=1, code="LOGIN1", telegram_user_id=555, username="bobby")

        self.db.refresh(client)
        self.assertEqual(client.telegram_user_id, "555")
        self.assertEqual(client.telegram_username, "bobby")
        record = self._record("url-login1")
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)

    # ── 2. NULL telegram_username still activates when numeric id exists ───
    def test_null_username_still_activates(self):
        client = self._make_client()
        self._make_link("url-login2")
        self._assign(client, "url-login2")

        self._login(chat_id=2, code="LOGIN1", telegram_user_id=666, username=None)

        self.db.refresh(client)
        self.assertIsNone(client.telegram_username)
        self.assertEqual(client.telegram_user_id, "666")
        record = self._record("url-login2")
        self.assertEqual(record.activation_status, "activated")

    # ── 3. later login safely no-ops already-consistent activated slugs ────
    def test_later_login_noops_consistent_slug(self):
        client = self._make_client(telegram_user_id="777")
        self._make_link("url-login3")
        self._assign(client, "url-login3")
        fixed_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.db.add(models.ActivationRecord(
            slug="url-login3", activation_token="tok3", owner_client_id=client.id,
            activation_status="activated", activated_at=fixed_time,
        ))
        self.db.commit()

        self._login(chat_id=3, code="LOGIN1", telegram_user_id=777)

        record = self._record("url-login3")
        self.assertEqual(record.activated_at.replace(tzinfo=timezone.utc), fixed_time)

    # ── 4. later login retries a previously incomplete eligible slug ───────
    def test_later_login_retries_incomplete_slug(self):
        client = self._make_client(telegram_user_id="888")
        self._make_link("url-login4")
        self._assign(client, "url-login4")
        # Simulate a slug that never got reconciled (e.g. helper wasn't
        # wired yet, or a prior attempt failed) — still unactivated/no-owner.
        self.db.add(models.ActivationRecord(slug="url-login4", activation_token="tok4"))
        self.db.commit()

        self._login(chat_id=4, code="LOGIN1", telegram_user_id=888)

        record = self._record("url-login4")
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)

    # ── 5. slug assigned after first login reconciles on a later login ─────
    def test_slug_assigned_after_first_login_reconciles_later(self):
        client = self._make_client()
        self._make_link("url-login5a")
        self._assign(client, "url-login5a")

        self._login(chat_id=5, code="LOGIN1", telegram_user_id=999)
        self.db.refresh(client)
        self.assertEqual(self._record("url-login5a").activation_status, "activated")

        # New slug assigned after the client's first login.
        self._make_link("url-login5b")
        self._assign(client, "url-login5b")
        self.assertIsNone(self._record("url-login5b"))

        # Later re-login (same identity) picks it up.
        self._login(chat_id=5, code="LOGIN1", telegram_user_id=999)
        record = self._record("url-login5b")
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)

    # ── 16. reconciliation failure does not prevent successful Bot login ───
    def test_reconciliation_failure_does_not_block_login(self):
        client = self._make_client()
        self._make_link("url-login6")
        self._assign(client, "url-login6")

        with patch.object(
            bot_runtime, "_reconcile_assigned_slug_activation",
            side_effect=RuntimeError("boom"),
        ):
            # The outer defense-in-depth guard in the login branch swallows
            # even a totally unexpected reconciliation failure — no
            # exception should escape, and the login must still complete
            # (the client reaches their normal slug menu/message).
            self._login(chat_id=6, code="LOGIN1", telegram_user_id=123)

        self.db.refresh(client)
        self.assertEqual(client.telegram_user_id, "123")
        self.assertTrue(self.mock_send.await_count >= 1)

    # ── 17. access-code reauthentication/rebinding behavior unchanged ──────
    def test_rebinding_on_relogin_unchanged(self):
        client = self._make_client(telegram_user_id="111", is_active=True)
        self._login(chat_id=7, code="LOGIN1", telegram_user_id=222, username="newname")
        self.db.refresh(client)
        self.assertEqual(client.telegram_user_id, "222")
        self.assertEqual(client.telegram_username, "newname")


# ---------------------------------------------------------------------------
# Part 3 — Admin read-model (link_admin.search_links) additions
# ---------------------------------------------------------------------------

class AdminReadModelTests(unittest.TestCase):
    def setUp(self):
        self.db_session, self.engine = _make_in_memory_session()
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

    def _make_client_row(self, name, access_code, telegram_user_id=None, telegram_username=None, is_active=True):
        c = models.BotClient(
            client_name=name, access_code=access_code,
            telegram_user_id=telegram_user_id, telegram_username=telegram_username,
            is_active=is_active,
        )
        self.db_session.add(c)
        self.db_session.commit()
        self.db_session.refresh(c)
        return c

    def _make_link(self, slug, phone, content_type="url"):
        self.db_session.add(models.RedirectLink(
            slug=slug, destination_url="https://x.example.com",
            content_type=content_type, phone_number=phone,
        ))
        self.db_session.commit()

    def _assign(self, client, slug):
        self.db_session.add(models.BotClientSlug(bot_client_id=client.id, slug=slug))
        self.db_session.commit()

    def _search_by_slug(self, slug):
        res = self.client.get("/admin/links/search", params={"slug": slug})
        self.assertEqual(res.status_code, 200)
        return res.json()["results"][0]

    # ── 18. Admin derives Old Client correctly ──────────────────────────────
    def test_old_client_derivation_fields(self):
        self._make_link("url-r1", "5559001")
        r = self._search_by_slug("url-r1")
        self.assertIsNone(r["activation"])
        self.assertIsNone(r["assigned_client"])

    # ── 19. Admin derives Awaiting Telegram Login correctly ────────────────
    def test_awaiting_telegram_login_derivation_fields(self):
        client = self._make_client_row("Carol", "CODE-C", telegram_user_id=None)
        self._make_link("url-r2", "5559002")
        self._assign(client, "url-r2")

        r = self._search_by_slug("url-r2")
        self.assertIsNotNone(r["assigned_client"])
        self.assertEqual(r["assigned_client"]["client_id"], client.id)
        self.assertFalse(r["assigned_client"]["telegram_linked"])
        self.assertNotIn("access_code", r["assigned_client"])

    # ── 20. Admin derives Activated correctly ───────────────────────────────
    def test_activated_derivation_fields(self):
        client = self._make_client_row("Dana", "CODE-D", telegram_user_id="42")
        self._make_link("url-r3", "5559003")
        self._assign(client, "url-r3")
        self.db_session.add(models.ActivationRecord(
            slug="url-r3", activation_token="tok-r3", owner_client_id=client.id,
            activation_status="activated", activated_at=datetime.now(timezone.utc),
        ))
        self.db_session.commit()

        r = self._search_by_slug("url-r3")
        self.assertTrue(r["assigned_client"]["telegram_linked"])
        self.assertEqual(r["activation"]["activation_status"], "activated")
        self.assertEqual(r["activation"]["owner_client_id"], client.id)

    # ── 21. Admin does not mislabel linked-but-inconsistent state ──────────
    def test_linked_but_inconsistent_state_is_distinguishable(self):
        client = self._make_client_row("Erin", "CODE-E", telegram_user_id="43")
        self._make_link("url-r4", "5559004")
        self._assign(client, "url-r4")
        # Telegram linked, but no ActivationRecord yet (reconciliation
        # hasn't run / failed) — the read-model must expose enough for the
        # frontend to distinguish this from both Old Client and Activated.
        r = self._search_by_slug("url-r4")
        self.assertTrue(r["assigned_client"]["telegram_linked"])
        self.assertIsNone(r["activation"])  # not Activated
        # (Old Client would require assigned_client to also be None — it isn't.)

    # ── 22. raw Bot access code never exposed through link search ──────────
    def test_access_code_never_exposed(self):
        client = self._make_client_row("Frank", "SECRET-CODE-XYZ", telegram_user_id="44")
        self._make_link("url-r5", "5559005")
        self._assign(client, "url-r5")

        res = self.client.get("/admin/links/search", params={"slug": "url-r5"})
        self.assertNotIn("SECRET-CODE-XYZ", res.text)
        self.assertNotIn("access_code", res.json()["results"][0]["assigned_client"])


# ---------------------------------------------------------------------------
# Part 4 — frontend structural checks (static/admin.html)
# ---------------------------------------------------------------------------

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminHtmlLifecycleDisplayTests(unittest.TestCase):
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

    def test_awaiting_telegram_login_label_present(self):
        body = self._build_result_card_body()
        self.assertIn("Awaiting Telegram Login", body)
        self.assertIn("Not linked yet", body)

    def test_activation_sync_required_and_ownership_conflict_labels_present(self):
        body = self._build_result_card_body()
        self.assertIn("Activation Sync Required", body)
        self.assertIn("Ownership Conflict", body)

    def test_old_client_label_still_present(self):
        body = self._build_result_card_body()
        self.assertIn("Old Client", body)

    def test_no_manual_activation_buttons_added(self):
        body = self._build_result_card_body()
        self.assertNotIn("Mark Activated", body)
        self.assertNotIn("Migrate & Activate", body)


if __name__ == "__main__":
    unittest.main()
