"""Regression tests for Activation Engine v1 Phase A4U (URL Content Setup).

Covers:
  - a url slug's Phase A3 callback continues into the URL-input state and
    sends a prompt right after the access code
  - a media slug never enters any A4U state
  - valid URL input reaches the confirmation state, shows the validated,
    trimmed destination (text.strip() only — no canonicalization), and
    offers a "Confirm" / "Change URL" inline keyboard as the primary
    confirmation path (typed YES/NO remains a compatibility fallback)
  - invalid-format and blocked (SHADZ/internal/loopback) URLs stay retryable
    without any database change
  - Confirm (button or typed YES) stores the confirmed URL only in the
    in-memory session and never touches
    ActivationRecord/RedirectLink/BotClientSlug
  - Change URL (button or typed NO) returns to URL input, clearing both
    pending_url and any confirmed_destination_url, without activating
    anything
  - archived/already-activated/wrong-type/invalid-session states fail closed
    for both the typed and callback confirmation paths
  - repeated confirmation delivery — same update_id, a different update_id,
    or a stray typed duplicate — creates no duplicate clients/assignments/
    side effects, never resets the session to awaiting_code, and never
    loses the confirmed URL
  - existing Phase A2/A3 "activate_" callback dispatch is unaffected by the
    new A4U callback routing

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

    def _run_a4u_callback(self, data, chat_id=42, callback_query_id="cbq-a4u"):
        cq = {"id": callback_query_id, "data": data, "message": {"chat": {"id": chat_id}}}
        asyncio.run(bot_runtime._handle_a4u_confirmation_callback(cq, self.db))

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
        self.assertNotEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        # Phase A4M: a media slug now continues into its own media-input
        # state (never A4U's URL-input state) — see
        # tests/test_activation_engine_phase_a4m.py for full coverage.
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)

    # -- valid URL input --------------------------------------------------

    def test_valid_url_reaches_confirmation_state(self):
        self._activate_url_slug()

        self._run_message(42, "https://merchant.example.com/product")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_CONFIRM_STATE)
        self.assertEqual(session["pending_url"], "https://merchant.example.com/product")

    def test_trimmed_url_shown_in_confirmation_message(self):
        # The stored/shown value is only text.strip() — no scheme/host/path
        # canonicalization. This asserts the trim behaviour, not "normalization".
        self._activate_url_slug()

        self._run_message(42, "  https://merchant.example.com/product  ")

        self.mock_send_message.assert_awaited_once_with(
            42,
            bot_runtime._ACTIVATION_URL_CONFIRM_PROMPT_TEXT.format(
                url="https://merchant.example.com/product"
            ),
            reply_markup=bot_runtime._a4u_confirmation_markup("tok-u1"),
        )

    def test_confirmation_prompt_includes_confirm_and_change_inline_actions(self):
        self._activate_url_slug("u1", "tok-u1")

        self._run_message(42, "https://merchant.example.com/product")

        call = self.mock_send_message.await_args
        markup = call.kwargs["reply_markup"]
        buttons = markup["inline_keyboard"][0]
        self.assertEqual(len(buttons), 2)
        self.assertEqual(buttons[0]["text"], "Confirm")
        self.assertEqual(buttons[0]["callback_data"], f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")
        self.assertEqual(buttons[1]["text"], "Change URL")
        self.assertEqual(buttons[1]["callback_data"], f"{bot_runtime._A4U_CHANGE_PAYLOAD_PREFIX}tok-u1")

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

    # -- confirmation: Confirm inline callback (primary flow) ----------------

    def test_confirm_callback_preserves_url_and_enters_post_confirmation_placeholder(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-1"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com/product")
        self.assertNotIn("pending_url", session)
        self.mock_answer.assert_awaited_once_with("cbq-1")
        self.mock_send_message.assert_awaited_once_with(
            42,
            bot_runtime._ACTIVATION_URL_SAVED_TEXT.format(url="https://merchant.example.com/product"),
        )

    def test_confirm_callback_does_not_write_any_a5_field(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://example.com")
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.activated_at)
        self.assertIsNone(record.owner_client_id)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    def test_confirm_callback_fails_closed_on_archived_slug(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4u", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_confirm_callback_fails_closed_on_activated_record(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        record.activation_status = "activated"
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4u", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        self.db.refresh(record)
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)

    def test_confirm_callback_fails_closed_when_content_type_becomes_media(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        link.content_type = "media"
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4u", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)

    def test_confirm_callback_fails_closed_on_token_mismatch_with_session(self):
        # A second, genuinely valid url slug/token exists — but chat 42's
        # session holds "tok-u1", not this one. A callback must not
        # succeed just because SOME valid record matches its token.
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self._make_link_and_record("u2", "url", "tok-u2")
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u2")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4u", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        record_u2 = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u2").first()
        self.assertEqual(record_u2.activation_status, "unactivated")
        self.assertIsNone(record_u2.owner_client_id)

    def test_confirm_callback_fails_closed_for_token_belonging_to_another_chat(self):
        # Chat 43 holds its own genuine, still-pending A4U confirmation
        # session for a different token. A callback carrying chat 43's
        # token but delivered against chat 42 (a different chat, whose own
        # session holds a different token) must fail closed for chat 42
        # and must not disturb chat 43's real session.
        self._activate_url_slug("u1", "tok-u1", chat_id=42, telegram_id=201)
        self._run_message(42, "https://merchant.example.com/product")

        self._activate_url_slug("u2", "tok-u2", chat_id=43, telegram_id=202)
        self._run_message(43, "https://other.example.com/product")
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u2", chat_id=42)

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4u", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()
        session_43 = bot_runtime._SESSIONS[43]
        self.assertEqual(session_43["state"], bot_runtime._ACTIVATION_URL_CONFIRM_STATE)
        self.assertEqual(session_43["pending_url"], "https://other.example.com/product")
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    def test_duplicate_confirm_callback_revalidates_db_state(self):
        # A duplicate Confirm tap must not bypass DB revalidation just
        # because the session already shows it as confirmed — if the slug
        # was archived in between, the duplicate must now fail closed too.
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-1"
        )
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-2"
        )

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-2", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    def test_duplicate_change_callback_revalidates_db_state(self):
        # A duplicate Change URL tap must likewise not bypass DB
        # revalidation just because the session already shows URL input.
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self._run_a4u_callback(
            f"{bot_runtime._A4U_CHANGE_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-1"
        )
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        record.activation_status = "activated"
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(
            f"{bot_runtime._A4U_CHANGE_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-2"
        )

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-2", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    # -- Change URL inline callback -------------------------------------------

    def test_change_url_callback_returns_to_input_and_clears_pending_and_confirmed(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(
            f"{bot_runtime._A4U_CHANGE_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-2"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.assertNotIn("pending_url", session)
        self.assertNotIn("confirmed_destination_url", session)
        self.mock_answer.assert_awaited_once_with("cbq-2")
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_URL_RETRY_TEXT)

    def test_change_url_callback_does_not_activate_anything(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")

        self._run_a4u_callback(f"{bot_runtime._A4U_CHANGE_PAYLOAD_PREFIX}tok-u1")

        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    # -- duplicate delivery: Confirm callback ---------------------------------

    def test_duplicate_confirm_callback_does_not_reset_session(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-1"
        )
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-2"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertNotEqual(session["state"], "awaiting_code")
        self.mock_answer.assert_awaited_once_with("cbq-2")
        self.mock_send_message.assert_not_awaited()

    def test_duplicate_confirm_callback_preserves_confirmed_destination_url(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com/product")
        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-1"
        )

        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-2"
        )
        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-3"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com/product")

    def test_duplicate_confirm_callback_creates_no_db_side_effect(self):
        self._activate_url_slug("u1", "tok-u1", telegram_id=401)
        self._run_message(42, "https://merchant.example.com/product")
        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-1"
        )

        self._run_a4u_callback(
            f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1", callback_query_id="cbq-2"
        )

        self.assertEqual(self.db.query(models.BotClient).count(), 1)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.activated_at)
        self.assertIsNone(record.owner_client_id)

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
        self.mock_send_message.reset_mock()

        # A stray repeat of the exact YES keyword after already moving past
        # confirmation must not resurrect the URL-confirm flow, mutate the
        # DB, create any BotClient/BotClientSlug rows, reset the session to
        # awaiting_code, or lose the confirmed URL. A brief repeat
        # acknowledgement is expected (the TEMPORARY A5 handoff placeholder).
        self._run_message(42, "YES")

        self.assertEqual(self.db.query(models.BotClient).count(), 1)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertNotEqual(session["state"], "awaiting_code")
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com")
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACTIVATION_URL_SAVED_TEXT.format(url="https://merchant.example.com")
        )

    def test_unrelated_text_after_confirmation_keeps_setup_state(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        self._run_message(42, "hello, what's next?")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)

    def test_unrelated_text_after_confirmation_preserves_confirmed_url(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        self._run_message(42, "hello, what's next?")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com")

    def test_unrelated_text_after_confirmation_does_not_reset_to_awaiting_code(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        self._run_message(42, "hello, what's next?")

        session = bot_runtime._SESSIONS[42]
        self.assertNotEqual(session["state"], "awaiting_code")
        self.assertIn(42, bot_runtime._SESSIONS)

    def test_unrelated_text_after_confirmation_does_not_change_pending_url(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        self._run_message(42, "https://attacker.example.com/should-not-be-saved")

        session = bot_runtime._SESSIONS[42]
        self.assertNotIn("pending_url", session)
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com")

    def test_unrelated_text_after_confirmation_sends_neutral_placeholder_reply(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")
        self.mock_send_message.reset_mock()

        self._run_message(42, "hello, what's next?")

        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACTIVATION_SETUP_AWAITING_TEXT
        )

    def test_unrelated_text_after_confirmation_creates_no_db_or_a5_side_effect(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        self._run_message(42, "hello, what's next?")
        self._run_message(42, "some more unrelated text")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://example.com")
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.activated_at)
        self.assertIsNone(record.owner_client_id)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    def test_repeated_unrelated_text_after_confirmation_remains_state_safe(self):
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        for text in ("hi", "status?", "NO", "cancel", "12345"):
            self._run_message(42, text)
            session = bot_runtime._SESSIONS[42]
            self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
            self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com")

    def test_typed_no_after_confirmation_does_not_change_url_or_reset_session(self):
        # "NO" only makes sense as a Change-URL signal from the
        # pre-confirmation state — once already confirmed, the TEMPORARY
        # placeholder treats it like any other unrelated text: no reset,
        # no change, no deletion of the confirmed URL.
        self._activate_url_slug("u1", "tok-u1")
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "YES")

        self._run_message(42, "NO")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com")

    def test_generic_setup_placeholder_session_retains_existing_behaviour(self):
        # A session sitting in the generic _ACTIVATION_SETUP_STATE
        # placeholder with neither confirmed_destination_url (A4U) nor
        # confirmed_activation_media (A4M) set — e.g. any content_type other
        # than url/media — must fall through to the pre-existing
        # "Unknown/expired state" reset, unaffected by either phase's
        # TEMPORARY handoff placeholder. Phase A4M now owns the media path
        # (see tests/test_activation_engine_phase_a4m.py), so this session
        # shape is forged directly rather than driven through the "media"
        # activate_ callback.
        bot_runtime._SESSIONS[42] = {
            "state": bot_runtime._ACTIVATION_SETUP_STATE,
            "activation_token": "tok-x",
            "bot_client_id": None,
            "content_type": "other",
        }
        self.mock_send_message.reset_mock()

        self._run_message(42, "some unrelated text")

        self.mock_send_message.assert_awaited_once_with(
            42, "Session expired. Please enter your access code."
        )
        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})

    def test_repeated_valid_submission_does_not_duplicate_clients(self):
        self._activate_url_slug("u1", "tok-u1", telegram_id=301)
        self._run_message(42, "https://merchant.example.com")
        self._run_message(42, "https://merchant.example.com")

        self.assertEqual(self.db.query(models.BotClient).count(), 1)


class A4UWebhookCallbackDispatchTests(unittest.TestCase):
    """Integration tests through the actual webhook route: prove the new
    a4uconfirm_/a4uchange_ callback_data prefixes are dispatched to
    bot_runtime._handle_a4u_confirmation_callback without disturbing the
    existing "activate_" (Phase A2/A3) callback dispatch, and that
    duplicate Confirm delivery is state-safe both under Telegram's
    update_id dedup and under a genuinely different update_id (i.e. the
    state transition itself is idempotent, not just the dedup cache)."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

        app = FastAPI()
        bot_runtime.register_bot_webhook_routes(app)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)

        bot_runtime._SEEN_UPDATE_IDS.clear()
        bot_runtime._SESSIONS.clear()
        self._env_patcher = patch.dict(os.environ, {"TELEGRAM_WEBHOOK_SECRET": "test-secret"})
        self._env_patcher.start()

        self._send_message_patcher = patch.object(bot_runtime, "_send_message", new_callable=AsyncMock)
        self.mock_send_message = self._send_message_patcher.start()
        self._answer_patcher = patch.object(bot_runtime, "_answer_callback_query", new_callable=AsyncMock)
        self.mock_answer = self._answer_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self._answer_patcher.stop()
        self._env_patcher.stop()
        self.db.close()
        bot_runtime._SEEN_UPDATE_IDS.clear()
        bot_runtime._SESSIONS.clear()

    def _post(self, body):
        return self.client.post(
            "/bot/telegram/webhook", json=body,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test-secret"},
        )

    def _activation_callback_body(self, update_id, callback_query_id, chat_id=42, telegram_id=900):
        return {
            "update_id": update_id,
            "callback_query": {
                "id": callback_query_id,
                "data": "activate_tok-u1",
                "message": {"chat": {"id": chat_id}},
                "from": {"id": telegram_id, "username": "shopper"},
            },
        }

    def _a4u_callback_body(self, update_id, callback_query_id, data, chat_id=42):
        return {
            "update_id": update_id,
            "callback_query": {
                "id": callback_query_id,
                "data": data,
                "message": {"chat": {"id": chat_id}},
            },
        }

    def _url_message_body(self, update_id, text, chat_id=42):
        return {
            "update_id": update_id,
            "message": {
                "chat": {"id": chat_id},
                "text": text,
                "from": {"id": 900, "username": "shopper"},
            },
        }

    def _seed_url_slug(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db.commit()

    def _drive_to_confirmation_state(self):
        """Seed the slug, run the Phase A3 "Activate Now" callback, then
        submit the destination URL — leaving the chat's session sitting in
        _ACTIVATION_URL_CONFIRM_STATE, ready for a Confirm/Change callback."""
        self._seed_url_slug()
        self._post(self._activation_callback_body(1001, "cbq-activate"))
        self._post(self._url_message_body(1002, "https://merchant.example.com/product"))

    def test_a4u_confirm_callback_is_dispatched_and_preserves_session(self):
        self._drive_to_confirmation_state()

        response = self._post(
            self._a4u_callback_body(1003, "cbq-confirm", f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")
        )

        self.assertEqual(response.status_code, 200)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com/product")

    def test_duplicate_confirm_callback_same_update_id_is_deduped(self):
        self._drive_to_confirmation_state()
        self.mock_answer.reset_mock()
        body = self._a4u_callback_body(
            2001, "cbq-confirm-dup", f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1"
        )

        self._post(body)
        self._post(body)

        self.assertEqual(self.mock_answer.await_count, 1)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com/product")

    def test_duplicate_confirm_callback_different_update_id_is_state_safe(self):
        # A genuinely repeated tap arrives as a distinct update_id (Telegram
        # never redelivers a second physical button press under the same
        # id) — update_id dedup alone would NOT catch this; the state
        # transition itself must be the thing that makes it safe.
        self._drive_to_confirmation_state()
        self.mock_answer.reset_mock()

        self._post(self._a4u_callback_body(
            3001, "cbq-confirm-a", f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1"
        ))
        self._post(self._a4u_callback_body(
            3002, "cbq-confirm-b", f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1"
        ))

        self.assertEqual(self.mock_answer.await_count, 2)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertNotEqual(session["state"], "awaiting_code")
        self.assertEqual(session["confirmed_destination_url"], "https://merchant.example.com/product")
        self.assertEqual(self.db.query(models.BotClient).count(), 1)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        self.assertEqual(record.activation_status, "unactivated")

    def test_existing_activate_now_callback_dispatch_is_unaffected(self):
        # Phase A2/A3's "activate_" callback_data must still resolve/create
        # the BotClient exactly as before — the new prefix-based routing
        # added for A4U must not intercept or alter it.
        self._seed_url_slug()

        response = self._post(self._activation_callback_body(4001, "cbq-activate"))

        self.assertEqual(response.status_code, 200)
        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "900").first()
        self.assertIsNotNone(client)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)

    def test_change_url_callback_dispatched_through_webhook(self):
        self._drive_to_confirmation_state()

        response = self._post(self._a4u_callback_body(
            5001, "cbq-change", f"{bot_runtime._A4U_CHANGE_PAYLOAD_PREFIX}tok-u1"
        ))

        self.assertEqual(response.status_code, 200)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.assertNotIn("confirmed_destination_url", session)


if __name__ == "__main__":
    unittest.main()
