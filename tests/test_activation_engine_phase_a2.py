"""Regression tests for Activation Engine v1 Phase A2 (First-Scan Telegram Entry).

Covers:
  - link_public.resolve_activation_redirect (the Activation Gateway gate used
    by main.py's /{slug} route for url/media slugs), including the 503
    fail-closed path when a gated slug's deep link can't be built
  - bot_runtime.build_activation_deep_link (deep-link construction)
  - bot_runtime._handle_message's /start deep-link payload handling
  - bot_runtime._handle_activation_callback (the "Activate Now" button press)
  - the webhook route's callback_query dispatch

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message and
bot_runtime._answer_callback_query are patched with AsyncMock everywhere
they're exercised; the webhook-route integration tests use a dedicated
FastAPI app (registering only register_bot_webhook_routes, matching the
tests/test_page_admin.py pattern) with get_db overridden to the same
isolated in-memory engine, so no real main.py or shadz.db is imported.
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import activation_i18n
import bot_runtime
import models
from database import Base, get_db
from link_public import resolve_activation_redirect


class ResolveActivationRedirectTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()
        self._env_patcher = patch.dict(
            os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"}
        )
        self._env_patcher.start()

    def tearDown(self):
        self._env_patcher.stop()
        self.db.close()

    def _make_link(self, slug, content_type, destination_url="https://example.com"):
        link = models.RedirectLink(slug=slug, destination_url=destination_url, content_type=content_type)
        self.db.add(link)
        self.db.commit()
        return link

    def _make_record(self, slug, token, status="unactivated"):
        record = models.ActivationRecord(slug=slug, activation_token=token, activation_status=status)
        self.db.add(record)
        self.db.commit()
        return record

    # 1. Unactivated url slug → Telegram activation deep link
    def test_unactivated_url_slug_redirects_to_activation_deep_link(self):
        self._make_link("u1", "url")
        self._make_record("u1", "tok-u1")

        response = resolve_activation_redirect("u1", self.db)

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "https://t.me/shadz_test_bot?start=activate_tok-u1")

    # 2. Unactivated media slug → Telegram activation deep link
    def test_unactivated_media_slug_redirects_to_activation_deep_link(self):
        self._make_link("m1", "media")
        self._make_record("m1", "tok-m1")

        response = resolve_activation_redirect("m1", self.db)

        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["location"], "https://t.me/shadz_test_bot?start=activate_tok-m1")

    # 3. Deep link carries the correct existing activation token
    def test_deep_link_carries_exact_activation_token(self):
        self._make_link("u2", "url")
        self._make_record("u2", "unique-token-xyz")

        response = resolve_activation_redirect("u2", self.db)

        self.assertIn("activate_unique-token-xyz", response.headers["location"])

    # 4. Activated url slug → gate is a no-op (falls through to legacy behaviour)
    def test_activated_url_slug_gate_is_noop(self):
        self._make_link("u3", "url")
        self._make_record("u3", "tok-u3", status="activated")

        response = resolve_activation_redirect("u3", self.db)

        self.assertIsNone(response)

    # 5. Activated media slug → gate is a no-op
    def test_activated_media_slug_gate_is_noop(self):
        self._make_link("m2", "media")
        self._make_record("m2", "tok-m2", status="activated")

        response = resolve_activation_redirect("m2", self.db)

        self.assertIsNone(response)

    # 6. Legacy url/media slug with no ActivationRecord → gate is a no-op
    def test_legacy_slug_without_activation_record_gate_is_noop(self):
        self._make_link("legacy1", "url")

        response = resolve_activation_redirect("legacy1", self.db)

        self.assertIsNone(response)

    def test_legacy_media_slug_without_activation_record_gate_is_noop(self):
        self._make_link("legacy2", "media")

        response = resolve_activation_redirect("legacy2", self.db)

        self.assertIsNone(response)

    # 7. page slugs never enter the Activation Engine — they can never carry
    # an ActivationRecord (models.create_activation_record_for_slug rejects
    # page in Phase A1), so the gate is always a no-op for them.
    def test_page_slug_has_no_activation_record_and_gate_is_noop(self):
        self._make_link("p1", "page")
        with self.assertRaises(ValueError):
            models.create_activation_record_for_slug(self.db, "p1", "tok-p1")

        response = resolve_activation_redirect("p1", self.db)

        self.assertIsNone(response)

    # Corrected behaviour: a gated (unactivated, activation-eligible) slug
    # must NEVER fall through to legacy url/media behaviour just because the
    # bot is misconfigured — it must fail closed with a 503 instead of
    # silently exposing the legacy destination_url/media.
    def test_missing_bot_username_fails_closed_with_503_for_url_slug(self):
        self._env_patcher.stop()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TELEGRAM_BOT_USERNAME", None)
            self._make_link("u4", "url", destination_url="https://secret-legacy-destination.example.com")
            self._make_record("u4", "tok-u4")

            with self.assertRaises(HTTPException) as ctx:
                resolve_activation_redirect("u4", self.db)

        self.assertEqual(ctx.exception.status_code, 503)
        # The 503 detail must never leak the legacy destination URL.
        self.assertNotIn("secret-legacy-destination", str(ctx.exception.detail))
        self._env_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"})
        self._env_patcher.start()

    def test_missing_bot_username_fails_closed_with_503_for_media_slug(self):
        self._env_patcher.stop()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TELEGRAM_BOT_USERNAME", None)
            self._make_link("m3", "media")
            self._make_record("m3", "tok-m3")

            with self.assertRaises(HTTPException) as ctx:
                resolve_activation_redirect("m3", self.db)

        self.assertEqual(ctx.exception.status_code, 503)
        self._env_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"})
        self._env_patcher.start()

    def test_invalid_token_fails_closed_with_503_for_url_slug(self):
        self._make_link("u5", "url")
        # A token that can't fit Telegram's deep-link payload format —
        # build_activation_deep_link fails safe (returns None) for this.
        self._make_record("u5", "x" * 60)

        with self.assertRaises(HTTPException) as ctx:
            resolve_activation_redirect("u5", self.db)

        self.assertEqual(ctx.exception.status_code, 503)

    def test_invalid_token_fails_closed_with_503_for_media_slug(self):
        self._make_link("m4", "media")
        self._make_record("m4", "has space")

        with self.assertRaises(HTTPException) as ctx:
            resolve_activation_redirect("m4", self.db)

        self.assertEqual(ctx.exception.status_code, 503)

    # Requirement 1: an invalid (non-empty, malformed) TELEGRAM_BOT_USERNAME
    # must fail closed identically to a missing one — both url and media.
    def test_invalid_bot_username_fails_closed_with_503_for_url_slug(self):
        self._env_patcher.stop()
        with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "not-a-valid-username"}):
            self._make_link("u6", "url")
            self._make_record("u6", "tok-u6")

            with self.assertRaises(HTTPException) as ctx:
                resolve_activation_redirect("u6", self.db)

        self.assertEqual(ctx.exception.status_code, 503)
        self._env_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"})
        self._env_patcher.start()

    def test_invalid_bot_username_fails_closed_with_503_for_media_slug(self):
        self._env_patcher.stop()
        with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "NotEndingInSuffix"}):
            self._make_link("m5", "media")
            self._make_record("m5", "tok-m5")

            with self.assertRaises(HTTPException) as ctx:
                resolve_activation_redirect("m5", self.db)

        self.assertEqual(ctx.exception.status_code, 503)
        self._env_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"})
        self._env_patcher.start()

    # Requirement 4: the controlled 503 must never leak any secret/content.
    def test_503_response_leaks_no_secret_or_content_url_slug(self):
        self._env_patcher.stop()
        with patch.dict(
            os.environ,
            {
                "TELEGRAM_BOT_TOKEN": "super-secret-bot-token",
                "TELEGRAM_WEBHOOK_SECRET": "super-secret-webhook-secret",
            },
            clear=False,
        ):
            os.environ.pop("TELEGRAM_BOT_USERNAME", None)
            self._make_link("u7", "url", destination_url="https://leak-check-destination.example.com/secret-path")
            self._make_record("u7", "leak-check-activation-token")

            with self.assertRaises(HTTPException) as ctx:
                resolve_activation_redirect("u7", self.db)

        detail = str(ctx.exception.detail)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertNotIn("leak-check-destination.example.com", detail)
        self.assertNotIn("secret-path", detail)
        self.assertNotIn("leak-check-activation-token", detail)
        self.assertNotIn("super-secret-bot-token", detail)
        self.assertNotIn("super-secret-webhook-secret", detail)
        self._env_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"})
        self._env_patcher.start()

    def test_503_response_leaks_no_secret_or_content_media_slug(self):
        self._env_patcher.stop()
        with patch.dict(
            os.environ,
            {
                "TELEGRAM_BOT_TOKEN": "super-secret-bot-token",
                "TELEGRAM_WEBHOOK_SECRET": "super-secret-webhook-secret",
            },
            clear=False,
        ):
            os.environ.pop("TELEGRAM_BOT_USERNAME", None)
            self._make_link("m6", "media")
            sm = models.SlugMedia(slug="m6", media_asset_id=999, is_active=True)
            self.db.add(sm)
            self.db.commit()
            self._make_record("m6", "leak-check-media-token")

            with self.assertRaises(HTTPException) as ctx:
                resolve_activation_redirect("m6", self.db)

        detail = str(ctx.exception.detail)
        self.assertEqual(ctx.exception.status_code, 503)
        self.assertNotIn("leak-check-media-token", detail)
        self.assertNotIn("999", detail)
        self.assertNotIn("super-secret-bot-token", detail)
        self.assertNotIn("super-secret-webhook-secret", detail)
        self._env_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_test_bot"})
        self._env_patcher.start()


class BuildActivationDeepLinkTests(unittest.TestCase):
    def test_builds_expected_deep_link(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_bot"}):
            link = bot_runtime.build_activation_deep_link("abc123")
        self.assertEqual(link, "https://t.me/shadz_bot?start=activate_abc123")

    def test_missing_username_fails_safe(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TELEGRAM_BOT_USERNAME", None)
            link = bot_runtime.build_activation_deep_link("abc123")
        self.assertIsNone(link)

    def test_oversized_payload_fails_safe(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_bot"}):
            link = bot_runtime.build_activation_deep_link("x" * 60)
        self.assertIsNone(link)

    def test_payload_with_invalid_characters_fails_safe(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_USERNAME": "shadz_bot"}):
            link = bot_runtime.build_activation_deep_link("has space")
        self.assertIsNone(link)


class NormalizeBotUsernameTests(unittest.TestCase):
    """Focused tests for bot_runtime._normalize_bot_username."""

    def test_valid_username(self):
        self.assertEqual(bot_runtime._normalize_bot_username("MyShadzBot"), "MyShadzBot")

    def test_valid_username_with_leading_at(self):
        self.assertEqual(bot_runtime._normalize_bot_username("@MyShadzBot"), "MyShadzBot")

    def test_invalid_characters_rejected(self):
        self.assertIsNone(bot_runtime._normalize_bot_username("My-Shadz-Bot"))
        self.assertIsNone(bot_runtime._normalize_bot_username("My Shadz Bot"))

    def test_too_short_rejected(self):
        # "abot" is 4 chars, below the 5-char minimum.
        self.assertIsNone(bot_runtime._normalize_bot_username("abot"))

    def test_too_long_rejected(self):
        self.assertIsNone(bot_runtime._normalize_bot_username("a" * 30 + "bot"))  # 33 chars

    def test_missing_bot_suffix_rejected(self):
        self.assertIsNone(bot_runtime._normalize_bot_username("MyShadzApp"))

    def test_missing_value_rejected(self):
        self.assertIsNone(bot_runtime._normalize_bot_username(""))
        self.assertIsNone(bot_runtime._normalize_bot_username(None))

    def test_bot_suffix_check_is_case_insensitive(self):
        self.assertEqual(bot_runtime._normalize_bot_username("MyShadzBOT"), "MyShadzBOT")


class ActivationPayloadBuilderTests(unittest.TestCase):
    """Focused tests for bot_runtime._build_activation_payload — the single
    shared builder used by both build_activation_deep_link and
    _activation_entry_markup, so callback_data can never diverge from the
    deep-link payload's validation."""

    def test_valid_token_builds_expected_payload(self):
        self.assertEqual(bot_runtime._build_activation_payload("abc123"), "activate_abc123")

    def test_exact_maximum_boundary_is_accepted(self):
        # prefix "activate_" = 9 bytes; 55-char token -> exactly 64 bytes total.
        token = "a" * 55
        payload = bot_runtime._build_activation_payload(token)
        self.assertIsNotNone(payload)
        self.assertEqual(len(payload.encode("utf-8")), 64)

    def test_oversized_payload_rejected(self):
        # 56-char token -> 65 bytes total, one over the limit.
        token = "a" * 56
        self.assertIsNone(bot_runtime._build_activation_payload(token))

    def test_invalid_characters_rejected(self):
        self.assertIsNone(bot_runtime._build_activation_payload("has space"))
        self.assertIsNone(bot_runtime._build_activation_payload("token/with/slashes"))

    def test_empty_token_rejected(self):
        self.assertIsNone(bot_runtime._build_activation_payload(""))
        self.assertIsNone(bot_runtime._build_activation_payload(None))

    def test_generated_payload_never_exceeds_64_utf8_bytes(self):
        for token in ("a", "abc123", "x" * 55, "under_score-token"):
            payload = bot_runtime._build_activation_payload(token)
            if payload is not None:
                self.assertLessEqual(len(payload.encode("utf-8")), 64)


class ActivationEntryMarkupTests(unittest.TestCase):
    """Focused tests proving the "Activate Now" button builder never emits
    invalid callback_data and fails safe (never truncates) instead."""

    def test_valid_token_produces_button_with_matching_callback_data(self):
        markup = bot_runtime._activation_entry_markup("tok-u1")
        self.assertIsNotNone(markup)
        button = markup["inline_keyboard"][0][0]
        self.assertEqual(button["text"], "Activate Now")
        self.assertEqual(button["callback_data"], "activate_tok-u1")

    def test_oversized_token_yields_no_markup_not_a_truncated_one(self):
        markup = bot_runtime._activation_entry_markup("x" * 56)
        self.assertIsNone(markup)

    def test_empty_token_yields_no_markup(self):
        self.assertIsNone(bot_runtime._activation_entry_markup(""))

    def test_generated_callback_data_never_exceeds_64_utf8_bytes(self):
        markup = bot_runtime._activation_entry_markup("a" * 55)
        button = markup["inline_keyboard"][0][0]
        self.assertLessEqual(len(button["callback_data"].encode("utf-8")), 64)


class HandleMessageActivationEntryTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()
        bot_runtime._SESSIONS.clear()

        self._send_message_patcher = patch.object(
            bot_runtime, "_send_message", new_callable=AsyncMock
        )
        self.mock_send_message = self._send_message_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    def _make_link_and_record(self, slug, content_type, token, status="unactivated"):
        link = models.RedirectLink(slug=slug, destination_url="https://example.com", content_type=content_type)
        self.db.add(link)
        self.db.commit()
        record = models.ActivationRecord(slug=slug, activation_token=token, activation_status=status)
        self.db.add(record)
        self.db.commit()
        return link, record

    def _run(self, text, chat_id=1, message=None):
        asyncio.run(
            bot_runtime._handle_message(chat_id, text, {"id": 999}, self.db, message or {"text": text})
        )

    # 9. Valid activation payload enters the Phase A2 flow — and must NOT
    # be placed into the ordinary Bot Client access-code login state.
    #
    # Hotfix H1F: the very first thing shown is now the language selector,
    # not the Phase A2 entry message/"Activate Now" button directly — see
    # tests/test_activation_engine_h1f.py for the language-selection
    # callback that reveals the (now localized) entry message afterward.
    def test_valid_activation_payload_shows_language_selector(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("/start activate_tok-u1")

        self.mock_send_message.assert_awaited_once()
        args, kwargs = self.mock_send_message.call_args
        self.assertIn("language", args[1].lower())
        self.assertIn("reply_markup", kwargs)
        # One button per supported language; English's callback_data must
        # carry the token so the callback handler can re-validate it
        # independently of session state.
        buttons = [b for row in kwargs["reply_markup"]["inline_keyboard"] for b in row]
        self.assertEqual(len(buttons), len(activation_i18n.SUPPORTED_LANGUAGES))
        english = next(b for b in buttons if b["text"] == "English")
        self.assertEqual(english["callback_data"], "actlang_en_tok-u1")

    def test_valid_activation_payload_does_not_set_awaiting_code(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("/start activate_tok-u1")

        self.assertNotEqual(bot_runtime._SESSIONS[1]["state"], "awaiting_code")

    def test_valid_activation_payload_sets_activation_specific_state(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("/start activate_tok-u1")

        self.assertEqual(
            bot_runtime._SESSIONS[1],
            {"state": "awaiting_activation_language", "activation_token": "tok-u1"},
        )

    # 10. Every invalid activation payload shows the SAME generic
    # activation-invalid message and clears any login state — never falls
    # back to the ordinary welcome/access-code prompt.
    def test_empty_token_shows_activation_invalid_and_no_login_state(self):
        self._run("/start activate_")

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_INVALID_LINK_TEXT
        )
        self.assertNotIn(1, bot_runtime._SESSIONS)

    def test_invalid_character_token_shows_activation_invalid_and_no_login_state(self):
        self._run("/start activate_bad!token")

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_INVALID_LINK_TEXT
        )
        self.assertNotIn(1, bot_runtime._SESSIONS)

    def test_oversized_token_shows_activation_invalid_and_no_login_state(self):
        self._run("/start activate_" + "x" * 60)

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_INVALID_LINK_TEXT
        )
        self.assertNotIn(1, bot_runtime._SESSIONS)

    def test_unknown_token_shows_activation_invalid_and_no_login_state(self):
        self._run("/start activate_no-such-token")

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_INVALID_LINK_TEXT
        )
        self.assertNotIn(1, bot_runtime._SESSIONS)

    def test_already_activated_token_shows_activation_invalid_and_no_login_state(self):
        self._make_link_and_record("u2", "url", "tok-u2", status="activated")

        self._run("/start activate_tok-u2")

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_INVALID_LINK_TEXT
        )
        self.assertNotIn(1, bot_runtime._SESSIONS)

    def test_valid_record_unbuildable_markup_shows_activation_invalid(self):
        # A record that exists and is unactivated, but whose token can't
        # produce safe callback_data (e.g. seeded directly, bypassing the
        # deep-link builder that would normally reject it first).
        self._make_link_and_record("u9", "url", "x" * 60)

        self._run("/start activate_" + "x" * 60)

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_INVALID_LINK_TEXT
        )
        self.assertNotIn(1, bot_runtime._SESSIONS)

    def test_invalid_activation_payload_clears_preexisting_session(self):
        bot_runtime._SESSIONS[1] = {"state": "awaiting_code"}

        self._run("/start activate_no-such-token")

        self.assertNotIn(1, bot_runtime._SESSIONS)

    def test_malformed_start_payload_still_shows_ordinary_welcome(self):
        # A /start payload that ISN'T an activation payload at all keeps the
        # existing access-code login flow completely unchanged.
        self._run("/start not-an-activation-payload")

        self.mock_send_message.assert_awaited_once_with(
            1, "Welcome to SHADZ. Please enter your access code."
        )
        self.assertEqual(bot_runtime._SESSIONS[1]["state"], "awaiting_code")

    # 11. Ordinary /start and access-code login keep working
    def test_plain_start_still_shows_welcome(self):
        self._run("/start")

        self.mock_send_message.assert_awaited_once_with(
            1, "Welcome to SHADZ. Please enter your access code."
        )
        self.assertEqual(bot_runtime._SESSIONS[1]["state"], "awaiting_code")

    def test_access_code_login_still_works_after_start(self):
        client = models.BotClient(client_name="Test Client", access_code="XYZ789", is_active=True)
        self.db.add(client)
        link = models.RedirectLink(slug="u3", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        from models import BotClientSlug
        self.db.add(BotClientSlug(bot_client_id=client.id, slug="u3"))
        self.db.commit()

        self._run("/start")
        self._run("XYZ789")

        # Exactly one assigned slug: auto-selected straight into its
        # management menu, never a numbered "reply with a number between
        # 1 and 1" list (see the Phase A5 live-test defect fix).
        self.assertEqual(self.mock_send_message.await_count, 2)
        self.assertEqual(bot_runtime._SESSIONS[1]["state"], "awaiting_new_url")


class ActivationConfirmationSessionFallthroughTests(unittest.TestCase):
    """Regression tests for the awaiting_activation_confirmation state
    handler — ordinary text while a chat holds an activation session must
    never leak into (or be mistaken for) Bot Client access-code login."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()
        self.SessionLocal = SessionLocal
        bot_runtime._SESSIONS.clear()

        self._send_message_patcher = patch.object(
            bot_runtime, "_send_message", new_callable=AsyncMock
        )
        self.mock_send_message = self._send_message_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    def _make_link_and_record(self, slug, content_type, token, status="unactivated"):
        link = models.RedirectLink(slug=slug, destination_url="https://example.com", content_type=content_type)
        self.db.add(link)
        self.db.commit()
        record = models.ActivationRecord(slug=slug, activation_token=token, activation_status=status)
        self.db.add(record)
        self.db.commit()
        return link, record

    def _run(self, text, chat_id=1):
        asyncio.run(
            bot_runtime._handle_message(chat_id, text, {"id": 999}, self.db, {"text": text})
        )

    def _set_activation_session(self, chat_id=1, token="tok-u1"):
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_activation_confirmation",
            "activation_token": token,
        }

    # 1. Ordinary text preserves the activation session unchanged.
    def test_ordinary_text_sends_reminder_and_preserves_activation_session(self):
        self._set_activation_session(token="tok-u1")

        self._run("hello")

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_CONFIRMATION_REMINDER_TEXT
        )
        self.assertEqual(
            bot_runtime._SESSIONS[1],
            {"state": "awaiting_activation_confirmation", "activation_token": "tok-u1"},
        )
        self.assertNotEqual(bot_runtime._SESSIONS[1]["state"], "awaiting_code")

    # 2. Access-code-looking text is not processed as a Bot Client access
    # code — the activation session is preserved and the same reminder sent.
    def test_access_code_looking_text_is_not_processed_as_login(self):
        client = models.BotClient(client_name="Test Client", access_code="XYZ789", is_active=True)
        self.db.add(client)
        self.db.commit()
        self._set_activation_session(token="tok-u1")

        self._run("XYZ789")

        self.mock_send_message.assert_awaited_once_with(
            1, bot_runtime._ACTIVATION_CONFIRMATION_REMINDER_TEXT
        )
        self.assertEqual(
            bot_runtime._SESSIONS[1],
            {"state": "awaiting_activation_confirmation", "activation_token": "tok-u1"},
        )
        # No login side-effect: the BotClient's telegram_user_id/username
        # must remain unset — only the "awaiting_code" branch sets those.
        self.db.refresh(client)
        self.assertIsNone(client.telegram_user_id)

    # 3. /start still explicitly resets to ordinary login, even from this state.
    def test_start_still_resets_to_ordinary_login(self):
        self._set_activation_session(token="tok-u1")

        self._run("/start")

        self.mock_send_message.assert_awaited_once_with(
            1, "Welcome to SHADZ. Please enter your access code."
        )
        self.assertEqual(bot_runtime._SESSIONS[1], {"state": "awaiting_code"})

    # 4. A second valid activation deep link replaces the stored token.
    def test_second_valid_activation_link_replaces_stored_token(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._make_link_and_record("u2", "url", "tok-u2")
        self._set_activation_session(token="tok-u1")

        self._run("/start activate_tok-u2")

        self.assertEqual(
            bot_runtime._SESSIONS[1],
            {"state": "awaiting_activation_language", "activation_token": "tok-u2"},
        )

    # 5. No A3+ database mutation occurs from any of the above.
    def test_no_database_mutation_from_fallthrough_handling(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._set_activation_session(token="tok-u1")

        self._run("hello")
        self._run("some-access-code-attempt")

        record = (
            self.db.query(models.ActivationRecord)
            .filter(models.ActivationRecord.slug == "u1")
            .first()
        )
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)
        self.assertEqual(self.db.query(models.BotClient).count(), 0)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)


class HandleActivationCallbackTests(unittest.TestCase):
    """Unit tests for bot_runtime._handle_activation_callback directly."""

    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

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

    def _make_link_and_record(self, slug, content_type, token, status="unactivated"):
        link = models.RedirectLink(slug=slug, destination_url="https://example.com", content_type=content_type)
        self.db.add(link)
        self.db.commit()
        record = models.ActivationRecord(slug=slug, activation_token=token, activation_status=status)
        self.db.add(record)
        self.db.commit()
        return link, record

    def _callback_query(self, data, callback_query_id="cbq1", chat_id=42):
        return {
            "id": callback_query_id,
            "data": data,
            "message": {"chat": {"id": chat_id}},
        }

    def test_valid_callback_without_telegram_identity_answers_query_and_rejects(self):
        # This fixture's callback_query carries no "from" block — Phase A3
        # must fail safe (no BotClient) rather than crash or guess an identity.
        self._make_link_and_record("u1", "url", "tok-u1")

        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._callback_query("activate_tok-u1", chat_id=42), self.db
            )
        )

        self.mock_answer.assert_awaited_once_with("cbq1")
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACTIVATION_MISSING_IDENTITY_TEXT
        )

    def test_valid_callback_performs_no_a3_actions(self):
        _, record = self._make_link_and_record("u1", "url", "tok-u1")

        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._callback_query("activate_tok-u1"), self.db
            )
        )

        self.db.refresh(record)
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)
        self.assertEqual(self.db.query(models.BotClient).count(), 0)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)

    def test_unknown_token_callback_answers_invalid_and_sends_no_message(self):
        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._callback_query("activate_no-such-token"), self.db
            )
        )

        self.mock_answer.assert_awaited_once_with(
            "cbq1", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()

    def test_already_activated_token_callback_answers_invalid(self):
        self._make_link_and_record("u2", "url", "tok-u2", status="activated")

        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._callback_query("activate_tok-u2"), self.db
            )
        )

        self.mock_answer.assert_awaited_once_with(
            "cbq1", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()

    def test_non_activation_callback_data_is_answered_and_ignored(self):
        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._callback_query("some_other_feature:123"), self.db
            )
        )

        self.mock_answer.assert_awaited_once_with("cbq1")
        self.mock_send_message.assert_not_awaited()

    # Requirement 3: malformed updates must never crash, and a callback
    # missing an id must never be "invented" an acknowledgement.
    def test_missing_callback_query_id_does_not_crash_and_is_not_answered(self):
        asyncio.run(
            bot_runtime._handle_activation_callback(
                {"data": "activate_tok-u1", "message": {"chat": {"id": 42}}}, self.db
            )
        )

        self.mock_answer.assert_not_awaited()

    def test_missing_data_does_not_crash(self):
        asyncio.run(
            bot_runtime._handle_activation_callback(
                {"id": "cbq1", "message": {"chat": {"id": 42}}}, self.db
            )
        )

        # No recognised activation payload -> answered once, no text, ignored.
        self.mock_answer.assert_awaited_once_with("cbq1")
        self.mock_send_message.assert_not_awaited()

    def test_missing_message_does_not_crash(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        asyncio.run(
            bot_runtime._handle_activation_callback(
                {"id": "cbq1", "data": "activate_tok-u1"}, self.db
            )
        )

        # Callback still answered; no chat to reply to, so no boundary message.
        self.mock_answer.assert_awaited_once_with("cbq1")
        self.mock_send_message.assert_not_awaited()

    def test_missing_chat_does_not_crash(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        asyncio.run(
            bot_runtime._handle_activation_callback(
                {"id": "cbq1", "data": "activate_tok-u1", "message": {}}, self.db
            )
        )

        self.mock_answer.assert_awaited_once_with("cbq1")
        self.mock_send_message.assert_not_awaited()

    def test_non_dict_callback_query_does_not_crash(self):
        for bad_value in ("just a string", None, 123, ["list", "value"]):
            with self.subTest(bad_value=bad_value):
                self.mock_answer.reset_mock()
                self.mock_send_message.reset_mock()
                asyncio.run(bot_runtime._handle_activation_callback(bad_value, self.db))
                self.mock_answer.assert_not_awaited()
                self.mock_send_message.assert_not_awaited()

    # Requirement 3: inbound callback_data must be format-validated through
    # the same shared validator BEFORE any DB lookup.
    def test_malformed_callback_data_rejected_before_db_lookup(self):
        with patch.object(
            bot_runtime, "_lookup_unactivated_record", wraps=bot_runtime._lookup_unactivated_record
        ) as spy_lookup:
            asyncio.run(
                bot_runtime._handle_activation_callback(
                    self._callback_query("activate_bad!token"), self.db
                )
            )

        spy_lookup.assert_not_called()
        self.mock_answer.assert_awaited_once_with(
            "cbq1", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()

    def test_oversized_callback_data_rejected_before_db_lookup(self):
        with patch.object(
            bot_runtime, "_lookup_unactivated_record", wraps=bot_runtime._lookup_unactivated_record
        ) as spy_lookup:
            asyncio.run(
                bot_runtime._handle_activation_callback(
                    self._callback_query("activate_" + "x" * 60), self.db
                )
            )

        spy_lookup.assert_not_called()
        self.mock_answer.assert_awaited_once_with(
            "cbq1", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()

    def test_empty_token_callback_data_rejected_before_db_lookup(self):
        with patch.object(
            bot_runtime, "_lookup_unactivated_record", wraps=bot_runtime._lookup_unactivated_record
        ) as spy_lookup:
            asyncio.run(
                bot_runtime._handle_activation_callback(self._callback_query("activate_"), self.db)
            )

        spy_lookup.assert_not_called()
        self.mock_answer.assert_awaited_once_with(
            "cbq1", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_malformed_callback_data_performs_no_db_mutation(self):
        self.assertEqual(self.db.query(models.ActivationRecord).count(), 0)
        self.assertEqual(self.db.query(models.BotClient).count(), 0)

        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._callback_query("activate_" + "x" * 60), self.db
            )
        )

        self.assertEqual(self.db.query(models.ActivationRecord).count(), 0)
        self.assertEqual(self.db.query(models.BotClient).count(), 0)


class WebhookCallbackDispatchTests(unittest.TestCase):
    """Integration test for the webhook route's callback_query branch —
    verifies actual route wiring (secret check, dedup, dispatch), not just
    the handler function in isolation. Registers only
    register_bot_webhook_routes on a throwaway FastAPI app with get_db
    overridden to an isolated in-memory engine — no main.py/real shadz.db
    import, matching the tests/test_page_admin.py pattern.
    """

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
        self._env_patcher = patch.dict(
            os.environ, {"TELEGRAM_WEBHOOK_SECRET": "test-secret"}
        )
        self._env_patcher.start()

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
        self._env_patcher.stop()
        self.db.close()
        bot_runtime._SEEN_UPDATE_IDS.clear()

    def _post(self, body):
        return self.client.post(
            "/bot/telegram/webhook",
            json=body,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test-secret"},
        )

    def test_webhook_dispatches_valid_activation_callback(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        record = models.ActivationRecord(slug="u1", activation_token="tok-u1")
        self.db.add(record)
        self.db.commit()

        response = self._post({
            "update_id": 1001,
            "callback_query": {
                "id": "cbq1",
                "data": "activate_tok-u1",
                "message": {"chat": {"id": 42}},
                "from": {"id": 555, "username": "shopper1", "first_name": "Sam"},
            },
        })

        self.assertEqual(response.status_code, 200)
        self.mock_answer.assert_awaited_once_with("cbq1")

        # Phase A3: a well-formed callback with a real Telegram identity now
        # resolves/creates a BotClient and sends its access code, instead of
        # the superseded Phase A2 boundary message.
        client = (
            self.db.query(models.BotClient)
            .filter(models.BotClient.telegram_user_id == "555")
            .first()
        )
        self.assertIsNotNone(client)
        # Phase A4U: a url slug also gets the URL-input prompt right after
        # the access code — see tests/test_activation_engine_phase_a4u.py.
        self.assertEqual(self.mock_send_message.await_count, 2)
        self.mock_send_message.assert_any_await(
            42, bot_runtime._ACCESS_CODE_READY_TEXT.format(code=client.access_code)
        )

    def test_webhook_rejects_callback_without_valid_secret(self):
        response = self.client.post(
            "/bot/telegram/webhook",
            json={"update_id": 1, "callback_query": {"id": "x", "data": "activate_y"}},
            headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"},
        )

        self.assertEqual(response.status_code, 401)
        self.mock_answer.assert_not_awaited()

    def test_webhook_dedupes_repeated_callback_update_id(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db.commit()

        body = {
            "update_id": 2002,
            "callback_query": {
                "id": "cbq2",
                "data": "activate_tok-u1",
                "message": {"chat": {"id": 42}},
            },
        }
        self._post(body)
        self._post(body)

        self.assertEqual(self.mock_answer.await_count, 1)


if __name__ == "__main__":
    unittest.main()
