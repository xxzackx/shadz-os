"""Regression tests for Activation Engine v1 Phase A5 (Activation Finalization).

Phase A5 runs INLINE, in the same request, immediately after A4U/A4M's own
Confirm step lands the session in _ACTIVATION_SETUP_STATE with confirmed
content — there is no second "Complete Activation" button/tap. A4U/A4M's own
Confirm handlers are untouched (they still only ever stash validated content
into the session); bot_runtime._finalize_activation_confirmation is called
right after them by the webhook route and by _handle_message's A4U
typed-YES compatibility branch. See tests/test_activation_engine_phase_a4u.py
and tests/test_activation_engine_phase_a4m.py for the updated
characterization tests proving immediate finalization on Confirm.

Covers here:
  - no second activation button/callback exists
  - BotClientSlug is created on success, reused if it already points at the
    same client, and a conflicting assignment to a different client fails
    closed with zero mutation
  - the activated slug immediately appears in the normal
    awaiting_slug_selection management flow (not "no active slugs")
  - URL and media transaction rollback includes the BotClientSlug
  - sequential duplicate delivery is idempotent (DB-truth based)
  - concurrent URL finalization: exactly one caller wins, the loser performs
    no content/ownership overwrite
  - concurrent media finalization: no duplicate active SlugMedia, no
    duplicate BotClientSlug, no owner/timestamp overwrite
  - foreign/stale sessions get only a generic response with no sensitive data

Uses isolated SQLite databases — never touches the real shadz.db. No network
calls: bot_runtime._send_message, _answer_callback_query,
_download_telegram_file, and _upload_bytes_to_r2 are all patched. The
concurrency tests use a temp file-backed SQLite database (rather than
":memory:") so two independent SQLAlchemy sessions can genuinely interleave,
with the interleaving driven deterministically via a mock side_effect rather
than real threads.
"""
import asyncio
import os
import sys
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient

import bot_runtime
import models
from database import Base, get_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


def _make_in_memory_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal()


class ActivationFinalizationDirectTests(unittest.TestCase):
    """Exercises bot_runtime._finalize_activation_confirmation directly,
    matching the direct-invocation style already used by the A4U/A4M test
    files (_run_a4u_callback / _run_a4m_callback)."""

    def setUp(self):
        self.db = _make_in_memory_session()
        bot_runtime._SESSIONS.clear()

        self._send_message_patcher = patch.object(
            bot_runtime, "_send_message", new_callable=AsyncMock
        )
        self.mock_send_message = self._send_message_patcher.start()
        self._answer_patcher = patch.object(
            bot_runtime, "_answer_callback_query", new_callable=AsyncMock
        )
        self.mock_answer = self._answer_patcher.start()
        self._download_patcher = patch.object(
            bot_runtime, "_download_telegram_file", new_callable=AsyncMock
        )
        self.mock_download = self._download_patcher.start()
        self.mock_download.return_value = b"fake-bytes"
        self._upload_patcher = patch.object(bot_runtime, "_upload_bytes_to_r2")
        self.mock_upload = self._upload_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self._answer_patcher.stop()
        self._download_patcher.stop()
        self._upload_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    # -- helpers --------------------------------------------------------

    def _make_client(self, is_active=True, access_code=None):
        access_code = access_code or f"CODE{self.db.query(models.BotClient).count()}"
        client = models.BotClient(
            client_name="Test Client", access_code=access_code,
            telegram_user_id="900", telegram_username="shopper", is_active=is_active,
        )
        self.db.add(client)
        self.db.commit()
        return client

    def _make_link_and_record(self, slug, content_type, token, status="unactivated", is_archived=False):
        link = models.RedirectLink(
            slug=slug, destination_url="https://example.com", content_type=content_type,
            is_archived=is_archived,
        )
        self.db.add(link)
        self.db.commit()
        record = models.ActivationRecord(slug=slug, activation_token=token, activation_status=status)
        self.db.add(record)
        self.db.commit()
        return link, record

    def _url_session(self, token, client_id, chat_id=42, confirmed_url="https://merchant.example.com/product"):
        bot_runtime._SESSIONS[chat_id] = {
            "state": bot_runtime._ACTIVATION_SETUP_STATE,
            "activation_token": token,
            "bot_client_id": client_id,
            "content_type": "url",
            "confirmed_destination_url": confirmed_url,
        }

    def _media_session(self, token, client_id, chat_id=42, pending=None):
        pending = pending or {
            "telegram_file_id": "file123", "media_type": "image", "mime_type": "image/jpeg",
            "original_filename": "telegram_image.jpg", "file_size": 1000,
        }
        bot_runtime._SESSIONS[chat_id] = {
            "state": bot_runtime._ACTIVATION_SETUP_STATE,
            "activation_token": token,
            "bot_client_id": client_id,
            "content_type": "media",
            "confirmed_activation_media": pending,
        }

    def _finalize(self, chat_id=42):
        asyncio.run(bot_runtime._finalize_activation_confirmation(chat_id, self.db))

    # -- no second button exists ------------------------------------------

    def test_no_a5_confirmation_callback_handler_exists(self):
        self.assertFalse(hasattr(bot_runtime, "_handle_a5_confirmation_callback"))
        self.assertFalse(hasattr(bot_runtime, "_a5_confirmation_markup"))
        self.assertFalse(hasattr(bot_runtime, "_A5_CONFIRM_PAYLOAD_PREFIX"))

    # -- successful URL finalization ---------------------------------------

    def test_successful_url_finalization_persists_destination_and_activates(self):
        link, record = self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-u1", client.id)

        self._finalize()

        self.db.refresh(link)
        self.db.refresh(record)
        self.assertEqual(link.destination_url, "https://merchant.example.com/product")
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)
        self.assertIsNotNone(record.activated_at)

    def test_url_finalization_clears_activation_session_data(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-u1", client.id)

        self._finalize()

        session = bot_runtime._SESSIONS[42]
        self.assertNotIn("activation_token", session)
        self.assertNotIn("confirmed_destination_url", session)

    # -- BotClientSlug assignment behaviour ---------------------------------

    def test_assignment_created_on_success(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-u1", client.id)

        self._finalize()

        assignment = self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").first()
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.bot_client_id, client.id)
        self.assertEqual(self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").count(), 1)

    def test_existing_same_client_assignment_is_reused_not_duplicated(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug="u1"))
        self.db.commit()
        self._url_session("tok-u1", client.id)

        self._finalize()

        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").count(), 1)

    def test_conflicting_client_assignment_fails_closed_with_no_mutation(self):
        link, record = self._make_link_and_record("u1", "url", "tok-u1")
        other_client = self._make_client()
        self.db.add(models.BotClientSlug(bot_client_id=other_client.id, slug="u1"))
        self.db.commit()
        session_client = self._make_client()
        self._url_session("tok-u1", session_client.id)

        self._finalize()

        self.db.refresh(record)
        self.db.refresh(link)
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertEqual(link.destination_url, "https://example.com")
        assignment = self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").first()
        self.assertEqual(assignment.bot_client_id, other_client.id)
        self.assertEqual(self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").count(), 1)

    def test_activated_slug_assigned_but_session_requires_fresh_login(self):
        # Live-test defect fix: activation must never leave the chat
        # automatically authenticated. The BotClientSlug assignment is
        # created immediately (so a subsequent access-code login sees the
        # slug right away — see test_bot_runtime_management_flow.py for
        # the end-to-end login-after-activation coverage), but the session
        # itself resets to awaiting_code, not awaiting_slug_selection.
        self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-u1", client.id)

        self._finalize()

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})
        assignment = self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").first()
        self.assertIsNotNone(assignment)
        self.assertEqual(assignment.bot_client_id, client.id)
        # Must not fall into the "no active slugs assigned" state — the
        # assignment above proves there is one.
        self.mock_send_message.assert_any_call(
            42, bot_runtime._ACTIVATION_COMPLETE_TEXT.format(code=client.access_code)
        )
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("no active slugs", call.args[1])

    # -- successful media finalization ---------------------------------------

    def test_successful_media_finalization_persists_asset_activates_and_assigns(self):
        link, record = self._make_link_and_record("m1", "media", "tok-m1")
        client = self._make_client()
        self._media_session("tok-m1", client.id)

        self._finalize()

        self.db.refresh(record)
        self.mock_download.assert_awaited_once_with("file123")
        self.mock_upload.assert_called_once()
        asset = self.db.query(models.MediaAsset).filter(models.MediaAsset.mime_type == "image/jpeg").first()
        self.assertIsNotNone(asset)
        sm = (
            self.db.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == "m1", models.SlugMedia.is_active == True)
            .first()
        )
        self.assertIsNotNone(sm)
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(
            self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "m1").count(), 1
        )

    def test_media_finalization_deactivates_prior_active_media(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        client = self._make_client()
        old_asset = models.MediaAsset(
            media_type="image", storage_provider="r2", storage_key="old/key",
            public_url="https://media.shadz.io/old/key", original_filename="old.jpg",
            mime_type="image/jpeg", file_size=10,
        )
        self.db.add(old_asset)
        self.db.commit()
        old_sm = models.SlugMedia(slug="m1", media_asset_id=old_asset.id, is_active=True)
        self.db.add(old_sm)
        self.db.commit()
        self._media_session("tok-m1", client.id)

        self._finalize()

        self.db.refresh(old_sm)
        self.assertFalse(old_sm.is_active)
        active_rows = (
            self.db.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == "m1", models.SlugMedia.is_active == True)
            .all()
        )
        self.assertEqual(len(active_rows), 1)

    # -- sequential idempotency -----------------------------------------------

    def test_sequential_duplicate_finalize_is_idempotent(self):
        link, record = self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-u1", client.id)
        self._finalize()
        first_activated_at = record.activated_at

        # Session was reset to awaiting_slug_selection by the first call —
        # re-seed a stale confirmed session (as if a duplicate delivery
        # raced in before the reset) to exercise the DB-truth guard itself.
        self._url_session("tok-u1", client.id)
        self._finalize()

        self.db.refresh(record)
        self.assertEqual(record.activated_at, first_activated_at)
        self.assertEqual(record.owner_client_id, client.id)
        self.assertEqual(self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").count(), 1)
        self.mock_send_message.reset_mock()

    def test_sequential_duplicate_media_finalize_creates_no_duplicate_rows(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        client = self._make_client()
        self._media_session("tok-m1", client.id)
        self._finalize()
        self.mock_download.reset_mock()
        self.mock_upload.reset_mock()

        self._media_session("tok-m1", client.id)
        self._finalize()

        self.assertEqual(self.db.query(models.MediaAsset).count(), 1)
        self.assertEqual(
            self.db.query(models.SlugMedia).filter(models.SlugMedia.is_active == True).count(), 1
        )
        self.assertEqual(
            self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "m1").count(), 1
        )
        self.mock_download.assert_not_awaited()
        self.mock_upload.assert_not_called()

    # -- rollback on failure, including the assignment ------------------------

    def test_rollback_on_url_persistence_failure_includes_assignment(self):
        link, record = self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-u1", client.id)

        with patch.object(self.db, "commit", side_effect=RuntimeError("boom")):
            self._finalize()

        self.db.rollback()
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://example.com")
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertEqual(self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").count(), 0)

    def test_rollback_on_media_persistence_failure_includes_assignment(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        client = self._make_client()
        self._media_session("tok-m1", client.id)

        with patch.object(self.db, "commit", side_effect=RuntimeError("boom")):
            self._finalize()

        self.db.rollback()
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)
        self.assertEqual(self.db.query(models.SlugMedia).count(), 0)
        self.assertEqual(self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "m1").count(), 0)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "unactivated")

    # -- foreign / stale session safety ---------------------------------------

    def test_token_session_mismatch_fails_closed_no_sensitive_data(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-other", client.id)

        self._finalize()

        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn(client.access_code, call.args[1])

    def test_stale_already_activated_record_is_not_overwritten(self):
        link, record = self._make_link_and_record("u1", "url", "tok-u1", status="activated")
        other_client = self._make_client()
        record.owner_client_id = other_client.id
        self.db.commit()
        session_client = self._make_client()
        self._url_session("tok-u1", session_client.id)

        self._finalize()

        self.db.refresh(record)
        self.db.refresh(link)
        self.assertEqual(record.owner_client_id, other_client.id)
        self.assertEqual(link.destination_url, "https://example.com")
        # Silent no-op — no access code or ownership detail is ever sent.
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn(session_client.access_code, call.args[1])

    def test_no_session_at_all_is_a_no_op(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._finalize()  # no _SESSIONS entry at all
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")
        self.mock_send_message.assert_not_awaited()

    def test_already_activated_session_does_not_retry_upload_or_finalization(self):
        # A forged/stale session sitting in _ACTIVATION_SETUP_STATE with
        # confirmed_activation_media, for a token whose record is already
        # "activated" (e.g. this exact finalize having already succeeded
        # moments ago) must never re-download/re-upload or re-persist.
        self._make_link_and_record("m1", "media", "tok-m1", status="activated")
        client = self._make_client()
        self._media_session("tok-m1", client.id)

        self._finalize()

        self.mock_download.assert_not_awaited()
        self.mock_upload.assert_not_called()
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)
        self.mock_send_message.assert_not_awaited()

    def test_no_duplicate_completion_message_on_repeat_finalize(self):
        link, record = self._make_link_and_record("u1", "url", "tok-u1")
        client = self._make_client()
        self._url_session("tok-u1", client.id)
        self._finalize()
        self.mock_send_message.assert_any_call(
            42, bot_runtime._ACTIVATION_COMPLETE_TEXT.format(code=client.access_code)
        )
        self.mock_send_message.reset_mock()

        # Re-seed a stale confirmed session for the same (now-activated)
        # token, as if a duplicate delivery raced in after the reset.
        self._url_session("tok-u1", client.id)
        self._finalize()

        for call in self.mock_send_message.await_args_list:
            self.assertNotEqual(
                call.args[1], bot_runtime._ACTIVATION_COMPLETE_TEXT.format(code=client.access_code)
            )

    def test_concurrent_loser_does_not_clear_winners_authenticated_session(self):
        # Simulates the exact race the session-race fix targets: a losing/
        # duplicate A4U Confirm tap re-validates against DB truth
        # (_lookup_unactivated_url_link) at the exact moment a concurrent
        # Phase A5 finalize has already committed and replaced
        # _SESSIONS[42] with the winner's normal post-activation
        # awaiting_code state (activation never keeps the chat
        # automatically authenticated). The loser's own fail-closed
        # cleanup must not clobber it.
        self._make_link_and_record("u1", "url", "tok-u1")
        winner_client = self._make_client()
        bot_runtime._SESSIONS[42] = {
            "state": bot_runtime._ACTIVATION_URL_CONFIRM_STATE,
            "activation_token": "tok-u1",
            "bot_client_id": winner_client.id,
            "content_type": "url",
            "pending_url": "https://merchant.example.com/product",
        }
        winner_session = {"state": "awaiting_code"}

        def fake_lookup(token, db):
            # By the time this duplicate/losing tap's DB-truth check runs,
            # a concurrent finalize has already committed and moved the
            # session to the winner's post-activation state.
            bot_runtime._SESSIONS[42] = winner_session
            return None

        with patch.object(bot_runtime, "_lookup_unactivated_url_link", side_effect=fake_lookup):
            cq = {
                "id": "cbq-x",
                "data": f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1",
                "message": {"chat": {"id": 42}},
            }
            asyncio.run(bot_runtime._handle_a4u_confirmation_callback(cq, self.db))

        self.assertIs(bot_runtime._SESSIONS[42], winner_session)
        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})

    def test_retry_requires_complete_matching_activation_context(self):
        # A session missing a required field (here: bot_client_id) must
        # fail closed without mutation — the retry surface only proceeds
        # for a complete, internally consistent activation context.
        link, record = self._make_link_and_record("u1", "url", "tok-u1")
        bot_runtime._SESSIONS[42] = {
            "state": bot_runtime._ACTIVATION_SETUP_STATE,
            "activation_token": "tok-u1",
            "content_type": "url",
            "confirmed_destination_url": "https://merchant.example.com/product",
            # bot_client_id deliberately missing
        }

        self._finalize()

        self.db.refresh(record)
        self.db.refresh(link)
        self.assertEqual(record.activation_status, "unactivated")
        self.assertEqual(link.destination_url, "https://example.com")

    def test_ordinary_access_code_login_is_not_intercepted(self):
        # A plain "awaiting_code" session sending its access code must be
        # handled entirely by the existing login flow — Phase A5's retry
        # surface is gated on _ACTIVATION_SETUP_STATE and structurally
        # cannot fire for a different state.
        client = self._make_client(access_code="LOGINCODE")
        bot_runtime._SESSIONS[42] = {"state": "awaiting_code"}

        asyncio.run(
            bot_runtime._handle_message(42, "LOGINCODE", {"id": 999}, self.db, {"text": "LOGINCODE"})
        )

        session = bot_runtime._SESSIONS[42]
        self.assertIn(session["state"], ("awaiting_slug_selection", "awaiting_code"))
        self.assertNotIn("activation_token", session)


class ConcurrentFinalizationTests(unittest.TestCase):
    """Simulates two concurrent finalize attempts for the same token using
    two independent SQLAlchemy sessions bound to the SAME temp file-backed
    SQLite database — ":memory:" can't model cross-connection concurrency.
    The interleaving is driven deterministically: a mock side_effect makes
    the "first" call run the "second" (concurrent) call to completion
    before continuing, rather than relying on real threads/timing."""

    def setUp(self):
        self._tmp_dir = tempfile.mkdtemp()
        self._db_path = os.path.join(self._tmp_dir, "concurrency_test.db")
        db_url = f"sqlite:///{self._db_path}"
        engine = create_engine(db_url, connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        self.db1 = SessionLocal()
        self.db2 = SessionLocal()
        bot_runtime._SESSIONS.clear()

        self._send_message_patcher = patch.object(
            bot_runtime, "_send_message", new_callable=AsyncMock
        )
        self.mock_send_message = self._send_message_patcher.start()
        self._upload_patcher = patch.object(bot_runtime, "_upload_bytes_to_r2")
        self.mock_upload = self._upload_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self._upload_patcher.stop()
        self.db1.close()
        self.db2.close()
        bot_runtime._SESSIONS.clear()

    def _make_client(self, db, access_code, is_active=True):
        client = models.BotClient(
            client_name="Test Client", access_code=access_code,
            telegram_user_id="900", telegram_username="shopper", is_active=is_active,
        )
        db.add(client)
        db.commit()
        return client

    def test_concurrent_url_finalization_only_one_wins(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db1.add(link)
        self.db1.commit()
        self.db1.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db1.commit()

        client1 = self._make_client(self.db1, "CODE1")
        client2 = self._make_client(self.db1, "CODE2")

        bot_runtime._SESSIONS[42] = {
            "state": bot_runtime._ACTIVATION_SETUP_STATE,
            "activation_token": "tok-u1",
            "bot_client_id": client1.id,
            "content_type": "url",
            "confirmed_destination_url": "https://winner.example.com/product",
        }

        call_depth = {"n": 0}

        async def run_concurrent():
            def side_effect(url):
                # Runs while db1's finalize is mid-flight, right before its
                # own atomic claim. Only the outer (db1) call takes this
                # branch — db2's own nested finalize call also passes
                # through this same patched function and must not recurse.
                call_depth["n"] += 1
                if call_depth["n"] == 1:
                    bot_runtime._SESSIONS[42] = {
                        "state": bot_runtime._ACTIVATION_SETUP_STATE,
                        "activation_token": "tok-u1",
                        "bot_client_id": client2.id,
                        "content_type": "url",
                        "confirmed_destination_url": "https://loser.example.com/product",
                    }
                    # db2 runs in its own thread/event loop — asyncio.run
                    # cannot nest inside db1's already-running loop, and a
                    # separate thread models an independent concurrent
                    # request more faithfully than manual coroutine driving.
                    t = threading.Thread(
                        target=lambda: asyncio.run(
                            bot_runtime._finalize_activation_confirmation(42, self.db2)
                        )
                    )
                    t.start()
                    t.join()
                return False

            with patch.object(bot_runtime, "_is_blocked_destination_url", side_effect=side_effect):
                await bot_runtime._finalize_activation_confirmation(42, self.db1)

        asyncio.run(run_concurrent())
        self.db1.rollback()
        self.db1.expire_all()

        record = self.db1.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        link = self.db1.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(record.activation_status, "activated")
        # The nested (db2) call ran to completion first, so it's the winner
        # — db1's own attempt must have lost the atomic compare-and-set and
        # rolled back without overwriting anything.
        self.assertEqual(record.owner_client_id, client2.id)
        self.assertEqual(link.destination_url, "https://loser.example.com/product")
        self.assertEqual(self.db1.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").count(), 1)
        assignment = self.db1.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "u1").first()
        self.assertEqual(assignment.bot_client_id, client2.id)

    def test_concurrent_media_finalization_only_winner_is_referenced(self):
        # Both concurrent attempts download AND upload to R2 before either
        # reaches the DB compare-and-set — external Telegram/R2 operations
        # can't be part of the SQLite transaction, so the loser's own
        # upload genuinely happens. This proves the DB side stays correct
        # regardless: exactly one MediaAsset/active SlugMedia is
        # referenced (the winner's), and the loser's uploaded object is a
        # documented, un-cleaned-up orphan in R2 — not a new cleanup
        # system, just an accepted, pre-existing class of risk (same as
        # T1C's own upload-then-DB-write ordering).
        link = models.RedirectLink(slug="m1", destination_url="https://example.com", content_type="media")
        self.db1.add(link)
        self.db1.commit()
        self.db1.add(models.ActivationRecord(slug="m1", activation_token="tok-m1"))
        self.db1.commit()

        client1 = self._make_client(self.db1, "CODE1")
        client2 = self._make_client(self.db1, "CODE2")

        def pending(file_id):
            return {
                "telegram_file_id": file_id, "media_type": "image", "mime_type": "image/jpeg",
                "original_filename": "telegram_image.jpg", "file_size": 1000,
            }

        bot_runtime._SESSIONS[42] = {
            "state": bot_runtime._ACTIVATION_SETUP_STATE,
            "activation_token": "tok-m1",
            "bot_client_id": client1.id,
            "content_type": "media",
            "confirmed_activation_media": pending("file-1"),
        }

        call_count = {"n": 0}

        async def fake_download(file_id):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # Concurrent "second request" completes fully first, using
                # its own session/db, before db1's own download returns.
                bot_runtime._SESSIONS[42] = {
                    "state": bot_runtime._ACTIVATION_SETUP_STATE,
                    "activation_token": "tok-m1",
                    "bot_client_id": client2.id,
                    "content_type": "media",
                    "confirmed_activation_media": pending("file-2"),
                }
                await bot_runtime._finalize_activation_confirmation(42, self.db2)
            return b"fake-bytes"

        with patch.object(bot_runtime, "_download_telegram_file", side_effect=fake_download):
            asyncio.run(bot_runtime._finalize_activation_confirmation(42, self.db1))

        record = self.db1.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client2.id)
        # Both the winner (db2) and the loser (db1) actually called
        # _upload_bytes_to_r2 — proving the concurrent-upload scenario this
        # test is about genuinely occurred — yet the DB reflects only one.
        self.assertEqual(self.mock_upload.call_count, 2)
        self.assertEqual(self.db1.query(models.MediaAsset).count(), 1)
        active_media = (
            self.db1.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == "m1", models.SlugMedia.is_active == True)
            .all()
        )
        self.assertEqual(len(active_media), 1)
        self.assertEqual(
            self.db1.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "m1").count(), 1
        )
        assignment = self.db1.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "m1").first()
        self.assertEqual(assignment.bot_client_id, client2.id)


if __name__ == "__main__":
    unittest.main()
