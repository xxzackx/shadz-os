"""Tests for UI3D-C1 Polish: Telegram display name + immediate assignment
reconciliation for already-linked BotClients.

Covers:
  1-7.  telegram_display_name capture/refresh (first+last, first-only,
        last-only, missing, never overwrites client_name, refreshes on
        change, numeric telegram_user_id stays authoritative for linked
        state regardless of display name/username).
  8.    Admin read model (link_admin.search_links) exposes
        telegram_display_name on both assigned_client and activation.owner.
  9-12. Admin OWNER line rendering (static/admin.html structural checks).
  13-20. bot_admin.assign_slug immediate-reconcile behavior for an
        already-linked BotClient (Activated, no second login, atomic
        transaction, conflict rollback, token/destination/media untouched).
  21.   Access-code login reconciliation still works as retry/recovery.
  22-25. Regression guards: Telegram self-activation flow (via
        _resolve_or_create_bot_client_for_telegram), H1G identity checks,
        H1A unassign, and page-slug assignment rejection are all unchanged.

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

import bot_admin
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
# 1-7: telegram_display_name capture / refresh
# ---------------------------------------------------------------------------

class BuildDisplayNameUnitTests(unittest.TestCase):
    # ── 1. first_name + last_name ───────────────────────────────────────────
    def test_first_and_last_name(self):
        self.assertEqual(
            bot_runtime._build_telegram_display_name("John", "Chan"), "John Chan"
        )

    # ── 2. first_name only ──────────────────────────────────────────────────
    def test_first_name_only(self):
        self.assertEqual(bot_runtime._build_telegram_display_name("John", None), "John")

    # ── 3. last_name only ────────────────────────────────────────────────────
    def test_last_name_only(self):
        self.assertEqual(bot_runtime._build_telegram_display_name(None, "Chan"), "Chan")

    # ── 4. missing display name handled safely ──────────────────────────────
    def test_neither_name_is_none(self):
        self.assertIsNone(bot_runtime._build_telegram_display_name(None, None))
        self.assertIsNone(bot_runtime._build_telegram_display_name("  ", "   "))


class LoginDisplayNamePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.db, self.engine = _make_in_memory_session()
        bot_runtime._SESSIONS.clear()
        self._send_patcher = patch.object(bot_runtime, "_send_message", new_callable=AsyncMock)
        self.mock_send = self._send_patcher.start()

    def tearDown(self):
        self._send_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    def _make_client(self, access_code="POL1", client_name="Testing", telegram_user_id=None):
        client = models.BotClient(
            client_name=client_name, access_code=access_code,
            telegram_user_id=telegram_user_id,
        )
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)
        return client

    def _login(self, chat_id, code, telegram_user_id, first_name=None, last_name=None, username=None):
        bot_runtime._SESSIONS[chat_id] = {"state": "awaiting_code"}
        asyncio.run(bot_runtime._handle_message(
            chat_id, code,
            {"id": telegram_user_id, "first_name": first_name, "last_name": last_name, "username": username},
            self.db, {"text": code},
        ))

    # ── 5. BotClient.client_name is never overwritten ──────────────────────
    def test_client_name_never_overwritten_on_login(self):
        client = self._make_client(client_name="Testing")
        self._login(chat_id=1, code="POL1", telegram_user_id=1, first_name="John", last_name="Chan")

        self.db.refresh(client)
        self.assertEqual(client.client_name, "Testing")
        self.assertEqual(client.telegram_display_name, "John Chan")

    # ── 6. display name refreshes when Telegram name changes ───────────────
    def test_display_name_refreshes_on_relogin(self):
        client = self._make_client(telegram_user_id="1")
        self._login(chat_id=2, code="POL1", telegram_user_id=1, first_name="Old", last_name="Name")
        self.db.refresh(client)
        self.assertEqual(client.telegram_display_name, "Old Name")

        self._login(chat_id=2, code="POL1", telegram_user_id=1, first_name="New", last_name="Name")
        self.db.refresh(client)
        self.assertEqual(client.telegram_display_name, "New Name")

    # ── 7. numeric telegram_user_id remains authoritative ──────────────────
    def test_numeric_id_authoritative_regardless_of_username_display_name(self):
        client = self._make_client()
        self._login(chat_id=3, code="POL1", telegram_user_id=999, first_name=None, last_name=None, username=None)

        self.db.refresh(client)
        self.assertEqual(client.telegram_user_id, "999")
        self.assertIsNone(client.telegram_username)
        self.assertIsNone(client.telegram_display_name)
        # Linked state is derivable from telegram_user_id alone.
        self.assertTrue(client.telegram_user_id is not None)


class SelfActivationDisplayNameTests(unittest.TestCase):
    """22. Regression guard: the Activation Engine's own client-resolution
    helper (used by the Telegram self-activation flow, not the access-code
    login flow) gains the same display_name refresh without any change to
    its existing reused/created/inactive/ambiguous contract.
    """
    def setUp(self):
        self.db, self.engine = _make_in_memory_session()

    def tearDown(self):
        self.db.close()

    def test_created_client_gets_display_name(self):
        status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, telegram_user_id="42", telegram_username="fridayy555",
            first_name="段坤", last_name=None,
        )
        self.assertEqual(status, "created")
        self.assertEqual(client.telegram_display_name, "段坤")
        self.db.commit()

    def test_reused_client_display_name_refreshes_without_touching_client_name(self):
        status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, telegram_user_id="43", telegram_username="u1", first_name="A", last_name=None,
        )
        self.db.commit()
        original_client_name = client.client_name

        status2, client2 = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, telegram_user_id="43", telegram_username="u1", first_name="B", last_name="C",
        )
        self.assertEqual(status2, "reused")
        self.assertEqual(client2.id, client.id)
        self.assertEqual(client2.telegram_display_name, "B C")
        self.assertEqual(client2.client_name, original_client_name)  # untouched

    def test_inactive_and_ambiguous_contract_unchanged(self):
        c1 = models.BotClient(
            client_name="X", access_code="C1", telegram_user_id="44", is_active=False,
        )
        self.db.add(c1)
        self.db.commit()
        status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, telegram_user_id="44", telegram_username=None, first_name=None, last_name=None,
        )
        self.assertEqual(status, "inactive")
        self.assertIsNone(client)


# ---------------------------------------------------------------------------
# 8: Admin read model exposes telegram_display_name
# ---------------------------------------------------------------------------

class AdminReadModelDisplayNameTests(unittest.TestCase):
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

    def _make_client_row(self, name, access_code, telegram_user_id=None,
                          telegram_username=None, telegram_display_name=None, is_active=True):
        c = models.BotClient(
            client_name=name, access_code=access_code,
            telegram_user_id=telegram_user_id, telegram_username=telegram_username,
            telegram_display_name=telegram_display_name, is_active=is_active,
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

    def test_assigned_client_exposes_telegram_display_name(self):
        client = self._make_client_row(
            "Testing", "CODE-P1", telegram_user_id="11",
            telegram_username="ttbet666", telegram_display_name="John Chan",
        )
        self._make_link("url-p1", "5559101")
        self._assign(client, "url-p1")

        r = self._search_by_slug("url-p1")
        self.assertEqual(r["assigned_client"]["telegram_display_name"], "John Chan")
        self.assertEqual(r["assigned_client"]["client_name"], "Testing")  # untouched
        self.assertNotIn("access_code", r["assigned_client"])

    def test_activation_owner_exposes_telegram_display_name(self):
        client = self._make_client_row(
            "Testing", "CODE-P2", telegram_user_id="8",
            telegram_username="fridayy555", telegram_display_name="段坤",
        )
        self._make_link("url-p2", "5559102")
        self._assign(client, "url-p2")
        self.db_session.add(models.ActivationRecord(
            slug="url-p2", activation_token="tok-p2", owner_client_id=client.id,
            activation_status="activated", activated_at=datetime.now(timezone.utc),
        ))
        self.db_session.commit()

        r = self._search_by_slug("url-p2")
        self.assertEqual(r["activation"]["owner_telegram_display_name"], "段坤")
        self.assertEqual(r["activation"]["owner_client_name"], "Testing")  # still present, untouched


# ---------------------------------------------------------------------------
# 9-12: Admin OWNER line rendering (structural checks on admin.html)
# ---------------------------------------------------------------------------

ADMIN_HTML_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "admin.html"
)


class AdminHtmlOwnerRenderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    def _owner_line_fn_body(self):
        match = re.search(
            r"function buildActivationOwnerLine\(a\) \{.*?\n    \}\n", self.html, re.DOTALL
        )
        self.assertIsNotNone(match, "buildActivationOwnerLine() not found")
        return match.group(0)

    # ── 9. renders Telegram display name instead of client_name ────────────
    def test_owner_line_uses_telegram_display_name_not_client_name(self):
        body = self._owner_line_fn_body()
        self.assertIn("owner_telegram_display_name", body)
        self.assertNotIn("owner_client_name", body)

    # ── 10. OWNER retains trailing #BotClient.id ────────────────────────────
    def test_owner_line_retains_trailing_client_id(self):
        body = self._owner_line_fn_body()
        self.assertIn("#${esc(a.owner_client_id)}", body)
        self.assertNotIn("telegram_user_id", body)  # never substitutes numeric Telegram id

    # ── 11. missing username renders safely ─────────────────────────────────
    # ── 12. missing Telegram display name renders safely ────────────────────
    def test_owner_line_has_placeholder_for_each_missing_slot(self):
        body = self._owner_line_fn_body()
        self.assertIn("owner_telegram_username ? `@${esc(a.owner_telegram_username)}` : '—'", body)
        self.assertIn("owner_telegram_display_name ? esc(a.owner_telegram_display_name) : '—'", body)

    def test_owner_line_reused_by_all_render_branches(self):
        # Confirms the shared helper is actually called from buildResultCard
        # (not just defined) for the fully-consistent Activated branch, the
        # sync/conflict branch's Activation Record Owner row, and the
        # no-assignment self-service branch — 1 definition + 3 call sites —
        # and the old duplicated ownerParts-with-client_name logic is fully
        # removed.
        self.assertEqual(self.html.count("buildActivationOwnerLine(a)"), 4)
        self.assertNotIn("ownerParts", self.html)

    def test_client_name_row_still_used_for_slug_card_client_field(self):
        # The unrelated slug-card "Client Name" field (r.client_name, the
        # phone-search client label) must remain untouched by this change.
        self.assertIn("['Client Name',  r.client_name]", self.html)


# ---------------------------------------------------------------------------
# 13-20: bot_admin.assign_slug immediate-reconcile for an already-linked
# BotClient
# ---------------------------------------------------------------------------

class AssignSlugReconciliationTests(unittest.TestCase):
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
        bot_admin.register_bot_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            db = self.SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app, raise_server_exceptions=False)
        self.db = self.SessionLocal()

    def tearDown(self):
        self.db.close()

    def _make_bot_client(self, telegram_user_id=None, access_code="ABC123"):
        client = models.BotClient(
            client_name="Test Client", access_code=access_code, telegram_user_id=telegram_user_id,
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

    def _assign(self, client_id, slug):
        return self.client.post(f"/admin/bot/clients/{client_id}/slugs", json={"slug": slug})

    def _record(self, slug):
        return self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == slug).first()

    # ── 13. assign to unlinked BotClient -> Awaiting Telegram Login (no record) ──
    def test_assign_to_unlinked_client_does_not_activate(self):
        client = self._make_bot_client(telegram_user_id=None)
        self._make_link("url-q1")

        res = self._assign(client.id, "url-q1")
        self.assertEqual(res.status_code, 201)
        self.assertIsNone(self._record("url-q1"))
        self.assertEqual(
            self.db.query(models.BotClientSlug)
            .filter(models.BotClientSlug.slug == "url-q1").count(),
            1,
        )

    # ── 14. assign to already-linked BotClient -> immediately Activated ────
    def test_assign_to_linked_client_immediately_activates(self):
        client = self._make_bot_client(telegram_user_id="777")
        self._make_link("url-q2")

        res = self._assign(client.id, "url-q2")
        self.assertEqual(res.status_code, 201)
        record = self._record("url-q2")
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)
        self.assertIsNotNone(record.activated_at)

    # ── 15. no second access-code login required ────────────────────────────
    def test_no_relogin_required_after_assignment(self):
        client = self._make_bot_client(telegram_user_id="778")
        self._make_link("url-q3")
        self._assign(client.id, "url-q3")
        # No login/session interaction performed at all — reconciliation
        # already happened synchronously inside the assign_slug call above.
        record = self._record("url-q3")
        self.assertEqual(record.activation_status, "activated")

    # ── 16. assignment + activation are atomic for linked client ───────────
    def test_assignment_and_activation_atomic_on_conflict(self):
        client = self._make_bot_client(telegram_user_id="779")
        other = self._make_bot_client(telegram_user_id="780", access_code="OTHER1")
        self._make_link("url-q4")
        self.db.add(models.ActivationRecord(
            slug="url-q4", activation_token="tok-q4", owner_client_id=other.id,
            activation_status="activated", activated_at=datetime.now(timezone.utc),
        ))
        self.db.commit()

        res = self._assign(client.id, "url-q4")
        self.assertEqual(res.status_code, 409)

        # Assignment must NOT exist — rolled back together with the failed
        # reconciliation attempt, never left in a normal-path state.
        self.assertEqual(
            self.db.query(models.BotClientSlug)
            .filter(models.BotClientSlug.slug == "url-q4").count(),
            0,
        )
        # ActivationRecord untouched — still owned by the other client.
        record = self._record("url-q4")
        self.assertEqual(record.owner_client_id, other.id)

    # ── 17. ownership conflict rolls back new assignment (same as 16, url) ──
    def test_conflict_response_is_clear_4xx(self):
        client = self._make_bot_client(telegram_user_id="781")
        other = self._make_bot_client(telegram_user_id="782", access_code="OTHER2")
        self._make_link("url-q5")
        self.db.add(models.ActivationRecord(
            slug="url-q5", activation_token="tok-q5", owner_client_id=other.id,
        ))  # unactivated + different owner
        self.db.commit()

        res = self._assign(client.id, "url-q5")
        self.assertEqual(res.status_code, 409)
        self.assertIn("conflict", res.json()["detail"].lower())

    # ── 18. activation token preserved ──────────────────────────────────────
    def test_existing_token_preserved_on_reconcile(self):
        client = self._make_bot_client(telegram_user_id="783")
        self._make_link("url-q6")
        self.db.add(models.ActivationRecord(slug="url-q6", activation_token="preserve-me"))
        self.db.commit()

        self._assign(client.id, "url-q6")
        self.assertEqual(self._record("url-q6").activation_token, "preserve-me")

    # ── 19. destination URL unchanged ───────────────────────────────────────
    def test_destination_url_unchanged_on_reconcile(self):
        client = self._make_bot_client(telegram_user_id="784")
        link = self._make_link("url-q7")
        self._assign(client.id, "url-q7")
        self.db.refresh(link)
        self.assertEqual(link.destination_url, "https://original.example.com")

    # ── 20. media attachment / SlugMedia unchanged ──────────────────────────
    def test_media_unchanged_on_reconcile(self):
        client = self._make_bot_client(telegram_user_id="785")
        self._make_link("media-q8", content_type="media")
        asset = models.MediaAsset(
            media_type="image", storage_key="k", public_url="https://media.shadz.io/k",
            original_filename="f.jpg", mime_type="image/jpeg", file_size=10,
        )
        self.db.add(asset)
        self.db.flush()
        sm = models.SlugMedia(slug="media-q8", media_asset_id=asset.id, is_active=True)
        self.db.add(sm)
        self.db.commit()

        self._assign(client.id, "media-q8")

        self.db.refresh(sm)
        self.assertTrue(sm.is_active)
        self.assertEqual(
            self.db.query(models.SlugMedia).filter(models.SlugMedia.slug == "media-q8").count(), 1
        )

    # ── 25. page slug assignment behavior unchanged ─────────────────────────
    def test_page_slug_assignment_still_rejected(self):
        client = self._make_bot_client(telegram_user_id="786")
        self._make_link("page-q9", content_type="page")

        res = self._assign(client.id, "page-q9")
        self.assertEqual(res.status_code, 400)
        self.assertIsNone(self._record("page-q9"))

    def test_archived_slug_assignment_still_rejected(self):
        client = self._make_bot_client(telegram_user_id="787")
        self._make_link("url-q10", is_archived=True)

        res = self._assign(client.id, "url-q10")
        self.assertEqual(res.status_code, 400)

    def test_duplicate_assignment_still_returns_409(self):
        client = self._make_bot_client(telegram_user_id="788")
        self._make_link("url-q11")
        self._assign(client.id, "url-q11")

        other = self._make_bot_client(telegram_user_id="789", access_code="OTHER3")
        res = self._assign(other.id, "url-q11")
        self.assertEqual(res.status_code, 409)


# ---------------------------------------------------------------------------
# 21: access-code login reconciliation still works as retry/recovery
# ---------------------------------------------------------------------------

class RetryRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.db, self.engine = _make_in_memory_session()
        bot_runtime._SESSIONS.clear()
        self._send_patcher = patch.object(bot_runtime, "_send_message", new_callable=AsyncMock)
        self.mock_send = self._send_patcher.start()

    def tearDown(self):
        self._send_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    def test_login_still_reconciles_a_slug_assigned_while_unlinked(self):
        client = models.BotClient(client_name="R", access_code="RETRY1")
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)

        link = models.RedirectLink(
            slug="url-retry1", destination_url="https://x.com", content_type="url",
        )
        self.db.add(link)
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug="url-retry1"))
        self.db.commit()

        # Still unlinked — no ActivationRecord should exist yet.
        self.assertIsNone(
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == "url-retry1").first()
        )

        bot_runtime._SESSIONS[10] = {"state": "awaiting_code"}
        asyncio.run(bot_runtime._handle_message(
            10, "RETRY1", {"id": 555, "first_name": "R", "last_name": None}, self.db, {"text": "RETRY1"},
        ))

        record = self.db.query(models.ActivationRecord).filter(
            models.ActivationRecord.slug == "url-retry1"
        ).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)


# ---------------------------------------------------------------------------
# 23-24: H1G identity checks and H1A unassign behavior unchanged
# ---------------------------------------------------------------------------

class RegressionGuardTests(unittest.TestCase):
    def setUp(self):
        self.db, self.engine = _make_in_memory_session()
        bot_runtime._SESSIONS.clear()
        self._send_patcher = patch.object(bot_runtime, "_send_message", new_callable=AsyncMock)
        self.mock_send = self._send_patcher.start()

    def tearDown(self):
        self._send_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    # ── 23. H1G identity behavior unchanged ─────────────────────────────────
    def test_h1g_session_invalid_when_telegram_identity_moves(self):
        client = models.BotClient(client_name="H1G", access_code="H1G1", telegram_user_id="1")
        self.db.add(client)
        self.db.commit()
        self.db.refresh(client)

        # A management session was authenticated by telegram id 1...
        bot_runtime._SESSIONS[20] = {
            "state": "awaiting_slug_selection",
            "bot_client_id": client.id,
            "slugs": [],
        }
        # ...but the code is later rebound to a different Telegram id (781)
        # via a fresh access-code login (elsewhere) — simulate by mutating
        # directly, matching what a real relogin would do.
        client.telegram_user_id = "781"
        self.db.commit()

        # Now the original chat (id 1) sends a message — H1G must reject it.
        asyncio.run(bot_runtime._handle_message(
            20, "1", {"id": 1}, self.db, {"text": "1"},
        ))
        self.assertEqual(bot_runtime._SESSIONS[20]["state"], "awaiting_code")

    # ── 24. H1A unassign behavior unchanged ─────────────────────────────────
    def test_h1a_unassign_still_resets_activation_and_preserves_token(self):
        app = FastAPI()
        router = APIRouter(prefix="/admin")
        bot_admin.register_bot_admin_routes(router)
        app.include_router(router)

        def _override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = _override_get_db
        api_client = TestClient(app, raise_server_exceptions=False)

        client = models.BotClient(client_name="H1A", access_code="H1A1", telegram_user_id="900")
        self.db.add(client)
        link = models.RedirectLink(
            slug="url-h1a", destination_url="https://original.example.com", content_type="url",
        )
        self.db.add(link)
        self.db.commit()

        assign_res = api_client.post(
            f"/admin/bot/clients/{client.id}/slugs", json={"slug": "url-h1a"}
        )
        self.assertEqual(assign_res.status_code, 201)
        record_before = self.db.query(models.ActivationRecord).filter(
            models.ActivationRecord.slug == "url-h1a"
        ).first()
        self.assertEqual(record_before.activation_status, "activated")
        token_before = record_before.activation_token

        unassign_res = api_client.delete(f"/admin/bot/clients/{client.id}/slugs/url-h1a")
        self.assertEqual(unassign_res.status_code, 200)

        record_after = self.db.query(models.ActivationRecord).filter(
            models.ActivationRecord.slug == "url-h1a"
        ).first()
        self.assertEqual(record_after.activation_status, "unactivated")
        self.assertIsNone(record_after.owner_client_id)
        self.assertIsNone(record_after.activated_at)
        self.assertEqual(record_after.activation_token, token_before)  # preserved

        self.db.refresh(link)
        self.assertEqual(link.destination_url, "")  # existing H1A reset behavior


if __name__ == "__main__":
    unittest.main()
