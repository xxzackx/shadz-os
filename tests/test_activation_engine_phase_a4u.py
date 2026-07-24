"""Regression tests for Activation Engine v1 Phase A4U (URL Content Setup).

Covers:
  - a url slug's Phase A3 callback continues into the URL-input state and
    sends a prompt right after the access code
  - a media slug never enters any A4U state
  - valid URL input reaches the confirmation state and shows the normalized
    destination
  - invalid-format and blocked (SHADZ/internal/loopback) URLs stay retryable
    without any database change
  - confirm (YES) stores the confirmed URL only in the in-memory session and
    never touches ActivationRecord/RedirectLink/BotClientSlug
  - retry/change (NO) returns to URL input without activating anything
  - archived/already-activated/wrong-type/invalid-session states fail closed
  - repeated updates create no duplicate clients/assignments/side effects

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message and
bot_runtime._answer_callback_query are patched with AsyncMock everywhere
they're exercised, matching the existing Phase A2/A3 test files.
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bot_runtime
import models
from database import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def _make_in_memory_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal()


class ActivationUrlSetupTests(unittest.TestCase):
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

    def tearDown(self):
        self._send_message_patcher.stop()
        self._answer_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    # -- helpers --------------------------------------------------------

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

    def _run_callback(self, data, chat_id=42, from_user=None, callback_query_id="cbq1"):
        cq = {"id": callback_query_id, "data": data, "message": {"chat": {"id": chat_id}}}
        if from_user is not None:
            cq["from"] = from_user
        asyncio.run(bot_runtime._handle_activation_callback(cq, self.db))

    def _run_message(self, chat_id, text):
        asyncio.run(
            bot_runtime._handle_message(chat_id, text, {"id": 999}, self.db, {"text": text})
        )

    def _activate_url_slug(self, slug="u1", token="tok-u1", chat_id=42, telegram_id=201):
        """Drive a url slug through A3 into the A4U URL-input state."""
        self._make_link_and_record(slug, "url", token)
        self._run_callback(f"activate_{token}", chat_id=chat_id, from_user={"id": telegram_id})
        self.mock_send_message.reset_mock()

    # -- entering the URL-input state ------------------------------------

    def test_eligible_url_slug_enters_url_input_state(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run_callback("activate_tok-u1", from_user={"id": 201})

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.mock_send_message.assert_any_await(42, bot_runtime._ACTIVATION_URL_PROMPT_TEXT)

    def test_media_slug_does_not_enter_a4u(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._run_callback("activate_tok-m1", from_user={"id": 202})

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertNotEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        # Only the access-code message — no URL prompt at all.
        self.assertEqual(self.mock_send_message.await_count, 1)

    # -- valid URL input --------------------------------------------------

    def test_valid_url_reaches_confirmation_state(self):
        self._activate_url_slug()

        self._run_message(42, "https://merchant.example.com/product")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_CONFIRM_STATE)
        self.assertEqual(session["pending_url"], "https://merchant.example.com/product")

    def test_normalization_shown_in_confirmation_message(self):
        self._activate_url_slug()

        self._run_message(42, "  https://merchant.example.com/product  ")

        self.mock_send_message.assert_awaited_once_with(
            42,
            bot_runtime._ACTIVATION_URL_CONFIRM_PROMPT_TEXT.format(
                url="https://merchant.example.com/product"
            ),
        )

    # -- invalid URL stays retryable ---------------------------------------

    def test_invalid_format_url_remains_retryable(self):
        self._activate_url_slug()

        self._run_message(42, "not-a-url")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACTIVATION_URL_INVALID_FORMAT_TEXT
        )

    def test_protected_internal_url_is_rejected(self):
        self._activate_url_slug()

        self._run_message(42, "https://shadz.io/some-slug")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_URL_BLOCKED_TEXT)

    def test_localhost_url_is_rejected(self):
        self._activate_url_slug()
        self._run_message(42, "http://localhost/abc")
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_URL_BLOCKED_TEXT)

    def test_loopback_ip_url_is_rejected(self):
        self._activate_url_slug()
        self._run_message(42, "http://127.0.0.1/abc")
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_URL_BLOCKED_TEXT)

    def test_invalid_input_makes_no_database_change(self):
        link, record = self._activate_url_slug("u1", "tok-u1"), None
        self._run_message(42, "not-a-url")

        link_row = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        record_row = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(link_row.destination_url, "https://example.com")
        self.assertEqual(record_row.activation_status, "unactivated")

    # -- confirmation: YES --------------------------------------------------

    def test_confirm_yes_stores_confirmed_url_in_session_only(self):
        self._activate_url_slug()
        self._run_message(42, "https://merchant.example.com/product")
        self.mock_send_message.reset_mock()

        self._run_message(42, "YES")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com/product")
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.mock_send_message.assert_awaited_once_with(
            42,
            bot_runtime._ACTIVATION_URL_SAVED_TEXT.format(url="https://merchant.example.com/product"),
        )

    def test_confirmation_does_not_mark_activation_complete_or_alter_redirect(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self._run_message(42, "YES")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()

        # Live redirect target is untouched — A4U never writes to it.
        self.assertEqual(link.destination_url, "https://example.com")
        # Activation lifecycle is untouched — A5's job.
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.activated_at)
        self.assertIsNone(record.owner_client_id)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    # -- confirmation: NO / retry --------------------------------------------

    def test_confirmation_no_returns_to_url_input_without_activating(self):
        self._activate_url_slug()
        self._run_message(42, "https://merchant.example.com/product")
        self.mock_send_message.reset_mock()

        self._run_message(42, "NO")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.assertNotIn("pending_url", session)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_URL_RETRY_TEXT)

    def test_confirmation_unrecognised_reply_stays_in_confirmation(self):
        self._activate_url_slug()
        self._run_message(42, "https://merchant.example.com/product")
        self.mock_send_message.reset_mock()

        self._run_message(42, "maybe")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_CONFIRM_STATE)
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACTIVATION_URL_CONFIRM_INVALID_REPLY_TEXT
        )

    def test_retry_can_be_followed_by_a_new_valid_url(self):
        self._activate_url_slug()
        self._run_message(42, "https://first.example.com")
        self._run_message(42, "NO")
        self._run_message(42, "https://second.example.com")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_CONFIRM_STATE)
        self.assertEqual(session["pending_url"], "https://second.example.com")

    # -- fail-closed cases ----------------------------------------------------

    def test_archived_slug_fails_closed_in_url_input_state(self):
        self._activate_url_slug("u1", "tok-u1")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        link.is_archived = True
        self.db.commit()

        self._run_message(42, "https://merchant.example.com")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_already_activated_record_fails_closed_in_url_input_state(self):
        self._activate_url_slug("u1", "tok-u1")
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        record.activation_status = "activated"
        self.db.commit()

        self._run_message(42, "https://merchant.example.com")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_wrong_type_slug_fails_closed_in_url_input_state(self):
        self._activate_url_slug("u1", "tok-u1")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        link.content_type = "media"
        self.db.commit()

        self._run_message(42, "https://merchant.example.com")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_archived_slug_fails_closed_in_confirmation_state(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_send_message.reset_mock()

        self._run_message(42, "YES")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_invalid_session_missing_token_fails_closed(self):
        bot_runtime._SESSIONS[42] = {"state": bot_runtime._ACTIVATION_URL_INPUT_STATE, "bot_client_id": None}

        self._run_message(42, "https://merchant.example.com")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    # -- idempotency ------------------------------------------------------

    def test_duplicate_confirm_yes_updates_create_no_side_effects(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        # A stray repeat of the YES message after already moving past
        # confirmation must not resurrect the URL-confirm flow, mutate the
        # DB, or create any BotClient/BotClientSlug rows.
        self._run_message(42, "YES")

        self.assertEqual(self.db.query(models.BotClient).count(), 1)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")

    def test_repeated_valid_submission_does_not_duplicate_clients(self):
        self._activate_url_slug("u1", "tok-u1", telegram_id=301)
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "https://merchant.example.com")

        self.assertEqual(self.db.query(models.BotClient).count(), 1)


if __name__ == "__main__":
    unittest.main()
