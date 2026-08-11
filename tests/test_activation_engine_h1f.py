"""Regression tests for Activation Engine v1 Hotfix H1F (Multilingual
Activation Flow).

Covers:
  - /start activate_<token> shows the language selector first, not the
    Phase A2 entry message directly
  - the selector offers exactly the 4 supported languages
    (activation_i18n.SUPPORTED_LANGUAGES)
  - a language-selector callback stores the chosen language on the session
    and reveals the localized entry message/button
  - the chosen language continues through Phase A3 (access code), A4U (url
    setup), and A4M (media setup) prompts and buttons
  - validation/error text and confirm/change buttons render in the chosen
    language
  - a missing or unrecognised session["language"] falls back to English
    rather than crashing or emitting an empty string
  - an invalid language-selector callback (bad code, bad token, malformed
    payload) is rejected without corrupting any existing session/DB state
  - activation token validation, BotClient resolution, ownership
    (BotClientSlug) and activation_status transition are unaffected by
    which language was chosen

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message and
bot_runtime._answer_callback_query are patched with AsyncMock, matching the
existing Activation Engine test files.
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import activation_i18n
import bot_runtime
import models
from database import Base


def _make_in_memory_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal()


class H1FTestBase(unittest.TestCase):
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

    # -- helpers ----------------------------------------------------------

    def _make_link_and_record(self, slug, content_type, token, status="unactivated"):
        link = models.RedirectLink(
            slug=slug, destination_url="https://example.com", content_type=content_type
        )
        self.db.add(link)
        self.db.commit()
        record = models.ActivationRecord(slug=slug, activation_token=token, activation_status=status)
        self.db.add(record)
        self.db.commit()
        return link, record

    def _run_message(self, text, chat_id=1, message=None):
        asyncio.run(
            bot_runtime._handle_message(chat_id, text, {"id": 999}, self.db, message or {"text": text})
        )

    def _run_start(self, token, chat_id=1):
        asyncio.run(bot_runtime._handle_activation_entry(chat_id, f"activate_{token}", self.db))

    def _lang_callback_query(self, lang, token, callback_query_id="cbq-lang", chat_id=1, from_user=None):
        return {
            "id": callback_query_id,
            "data": f"actlang_{lang}_{token}",
            "message": {"chat": {"id": chat_id}},
            "from": from_user or {"id": 555, "username": "shopper1", "first_name": "Sam"},
        }

    def _run_lang_callback(self, lang, token, **kwargs):
        asyncio.run(
            bot_runtime._handle_activation_language_callback(
                self._lang_callback_query(lang, token, **kwargs), self.db
            )
        )

    def _activate_now_callback_query(self, token, callback_query_id="cbq-act", chat_id=1, from_user=None):
        return {
            "id": callback_query_id,
            "data": f"activate_{token}",
            "message": {"chat": {"id": chat_id}},
            "from": from_user or {"id": 555, "username": "shopper1", "first_name": "Sam"},
        }

    def _run_activate_now(self, token, **kwargs):
        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._activate_now_callback_query(token, **kwargs), self.db
            )
        )

    def _select_language_and_activate(self, token, lang, chat_id=1):
        """Full happy-path setup: /start -> pick lang -> tap Activate Now."""
        self._run_start(token, chat_id=chat_id)
        self._run_lang_callback(lang, token, chat_id=chat_id)
        self.mock_send_message.reset_mock()
        self._run_activate_now(token, chat_id=chat_id)

    def _run_a4u_callback(self, data, chat_id=1, callback_query_id="cbq-a4u"):
        cq = {"id": callback_query_id, "data": data, "message": {"chat": {"id": chat_id}}}
        asyncio.run(bot_runtime._handle_a4u_confirmation_callback(cq, self.db))

    def _run_a4m_callback(self, data, chat_id=1, callback_query_id="cbq-a4m"):
        cq = {"id": callback_query_id, "data": data, "message": {"chat": {"id": chat_id}}}
        asyncio.run(bot_runtime._handle_a4m_confirmation_callback(cq, self.db))


class LanguageSelectorEntryTests(H1FTestBase):
    def test_start_shows_language_selector_first(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run_start("tok-u1")

        self.mock_send_message.assert_awaited_once()
        args, kwargs = self.mock_send_message.call_args
        self.assertEqual(args[1], activation_i18n.text("LANGUAGE_PROMPT", "en"))
        self.assertIn("reply_markup", kwargs)
        self.assertEqual(
            bot_runtime._SESSIONS[1],
            {"state": bot_runtime._ACTIVATION_LANGUAGE_SELECT_STATE, "activation_token": "tok-u1"},
        )

    def test_selector_has_exactly_4_supported_languages(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run_start("tok-u1")

        _, kwargs = self.mock_send_message.call_args
        buttons = [b for row in kwargs["reply_markup"]["inline_keyboard"] for b in row]
        self.assertEqual(len(buttons), 4)
        self.assertEqual(len(activation_i18n.SUPPORTED_LANGUAGES), 4)
        expected_labels = {label for _, label in activation_i18n.SUPPORTED_LANGUAGES}
        self.assertEqual({b["text"] for b in buttons}, expected_labels)
        expected_codes = {f"actlang_{code}_tok-u1" for code, _ in activation_i18n.SUPPORTED_LANGUAGES}
        self.assertEqual({b["callback_data"] for b in buttons}, expected_codes)

    def test_selector_renders_as_a_clean_2x2_grid(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run_start("tok-u1")

        _, kwargs = self.mock_send_message.call_args
        rows = kwargs["reply_markup"]["inline_keyboard"]
        self.assertEqual(len(rows), 2)
        self.assertEqual([len(row) for row in rows], [2, 2])
        # Row order follows activation_i18n.SUPPORTED_LANGUAGES order.
        expected_row1 = [label for _, label in activation_i18n.SUPPORTED_LANGUAGES[:2]]
        expected_row2 = [label for _, label in activation_i18n.SUPPORTED_LANGUAGES[2:4]]
        self.assertEqual([b["text"] for b in rows[0]], expected_row1)
        self.assertEqual([b["text"] for b in rows[1]], expected_row2)

    def test_invalid_token_shows_generic_invalid_message_not_selector(self):
        self._run_start("no-such-token")

        self.mock_send_message.assert_awaited_once_with(1, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)
        self.assertNotIn(1, bot_runtime._SESSIONS)


class LanguageSelectionCallbackTests(H1FTestBase):
    def test_language_callback_stores_selected_language_and_shows_localized_entry(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run_start("tok-u1")
        self.mock_send_message.reset_mock()

        self._run_lang_callback("km", "tok-u1")

        self.mock_answer.assert_awaited_once_with("cbq-lang")
        self.assertEqual(
            bot_runtime._SESSIONS[1],
            {
                "state": "awaiting_activation_confirmation",
                "activation_token": "tok-u1",
                "language": "km",
            },
        )
        self.mock_send_message.assert_awaited_once()
        args, kwargs = self.mock_send_message.call_args
        self.assertEqual(args[1], activation_i18n.text("ENTRY", "km"))
        button = kwargs["reply_markup"]["inline_keyboard"][0][0]
        self.assertEqual(button["text"], activation_i18n.button("ACTIVATE_NOW", "km"))
        self.assertEqual(button["callback_data"], "activate_tok-u1")

    def test_each_supported_language_can_be_selected(self):
        for code, _ in activation_i18n.SUPPORTED_LANGUAGES:
            with self.subTest(lang=code):
                bot_runtime._SESSIONS.clear()
                self.mock_send_message.reset_mock()
                self.mock_answer.reset_mock()
                self._make_link_and_record(f"u-{code}", "url", f"tok-{code}")

                self._run_start(f"tok-{code}")
                self._run_lang_callback(code, f"tok-{code}")

                self.assertEqual(bot_runtime._SESSIONS[1]["language"], code)
                args, _ = self.mock_send_message.call_args
                self.assertEqual(args[1], activation_i18n.text("ENTRY", code))

    def test_invalid_language_code_rejected_without_corrupting_session(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run_start("tok-u1")
        session_before = dict(bot_runtime._SESSIONS[1])
        self.mock_send_message.reset_mock()

        # "xx" is not one of the 4 supported codes.
        self._run_lang_callback("xx", "tok-u1")

        self.mock_answer.assert_awaited_once_with(
            "cbq-lang", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()
        # The pre-existing language-select session must be untouched — an
        # invalid selector tap is a no-op, not a session reset.
        self.assertEqual(bot_runtime._SESSIONS[1], session_before)

    def test_unknown_token_rejected_without_creating_bot_client(self):
        self._run_lang_callback("km", "no-such-token")

        self.mock_answer.assert_awaited_once_with(
            "cbq-lang", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()
        self.assertEqual(self.db.query(models.BotClient).count(), 0)

    def test_already_activated_token_rejected(self):
        self._make_link_and_record("u2", "url", "tok-u2", status="activated")

        self._run_lang_callback("id", "tok-u2")

        self.mock_answer.assert_awaited_once_with(
            "cbq-lang", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.mock_send_message.assert_not_awaited()

    def test_non_actlang_callback_data_is_ignored(self):
        asyncio.run(
            bot_runtime._handle_activation_language_callback(
                {"id": "cbq-x", "data": "activate_tok-u1", "message": {"chat": {"id": 1}}}, self.db
            )
        )
        self.mock_answer.assert_awaited_once_with("cbq-x")
        self.mock_send_message.assert_not_awaited()

    def test_malformed_callback_query_does_not_crash(self):
        for bad_value in ("just a string", None, 123, ["list"]):
            with self.subTest(bad_value=bad_value):
                self.mock_answer.reset_mock()
                self.mock_send_message.reset_mock()
                asyncio.run(bot_runtime._handle_activation_language_callback(bad_value, self.db))
                self.mock_answer.assert_not_awaited()
                self.mock_send_message.assert_not_awaited()


class LanguagePersistsThroughUrlActivationTests(H1FTestBase):
    def test_selected_language_continues_through_access_code_and_url_prompt(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        self._select_language_and_activate("tok-u1", "id")

        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "555").first()
        self.assertIsNotNone(client)
        self.assertEqual(bot_runtime._SESSIONS[1]["language"], "id")
        self.assertEqual(bot_runtime._SESSIONS[1]["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.assertEqual(self.mock_send_message.await_count, 2)
        self.mock_send_message.assert_any_await(
            1, activation_i18n.text("ACCESS_CODE_READY", "id", code=client.access_code)
        )
        self.mock_send_message.assert_any_await(1, activation_i18n.text("URL_PROMPT", "id"))

    def test_invalid_url_format_uses_selected_language(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._select_language_and_activate("tok-u1", "km")
        self.mock_send_message.reset_mock()

        self._run_message("not a url at all!!", chat_id=1)

        self.mock_send_message.assert_awaited_once_with(
            1, activation_i18n.text("URL_INVALID_FORMAT", "km")
        )

    def test_confirmation_prompt_and_buttons_use_selected_language(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._select_language_and_activate("tok-u1", "id")
        self.mock_send_message.reset_mock()

        self._run_message("example.com", chat_id=1)

        self.mock_send_message.assert_awaited_once()
        args, kwargs = self.mock_send_message.call_args
        self.assertEqual(
            args[1], activation_i18n.text("URL_CONFIRM_PROMPT", "id", url="https://example.com")
        )
        confirm_btn, change_btn = kwargs["reply_markup"]["inline_keyboard"][0]
        self.assertEqual(confirm_btn["text"], activation_i18n.button("CONFIRM", "id"))
        self.assertEqual(change_btn["text"], activation_i18n.button("CHANGE_URL", "id"))

    def test_url_activation_completes_with_correct_ownership_regardless_of_language(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._select_language_and_activate("tok-u1", "zh-Hans")
        self._run_message("example.com", chat_id=1)
        self.mock_send_message.reset_mock()

        self._run_message("yes", chat_id=1)

        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "u1").first()
        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "555").first()
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(record.owner_client_id, client.id)
        self.assertIsNotNone(record.activated_at)
        assignment = (
            self.db.query(models.BotClientSlug)
            .filter(models.BotClientSlug.slug == "u1", models.BotClientSlug.bot_client_id == client.id)
            .first()
        )
        self.assertIsNotNone(assignment)
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://example.com")
        self.mock_send_message.assert_any_await(
            1, activation_i18n.text("COMPLETE", "zh-Hans", code=client.access_code)
        )


class LanguagePersistsThroughMediaActivationTests(H1FTestBase):
    def test_selected_language_continues_through_access_code_and_media_prompt(self):
        self._make_link_and_record("m1", "media", "tok-m1")

        self._select_language_and_activate("tok-m1", "km")

        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "555").first()
        self.assertEqual(bot_runtime._SESSIONS[1]["language"], "km")
        self.assertEqual(bot_runtime._SESSIONS[1]["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.mock_send_message.assert_any_await(
            1, activation_i18n.text("ACCESS_CODE_READY", "km", code=client.access_code)
        )
        self.mock_send_message.assert_any_await(1, activation_i18n.text("MEDIA_PROMPT", "km"))

    def test_unsupported_media_text_uses_selected_language(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._select_language_and_activate("tok-m1", "id")
        self.mock_send_message.reset_mock()

        self._run_message("just some text", chat_id=1, message={"text": "just some text"})

        self.mock_send_message.assert_awaited_once_with(
            1, activation_i18n.text("MEDIA_UNSUPPORTED", "id")
        )

    def test_media_confirm_buttons_use_selected_language(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._select_language_and_activate("tok-m1", "zh-Hans")
        self.mock_send_message.reset_mock()

        message = {
            "photo": [{"file_id": "file123", "file_size": 1000}],
        }
        self._run_message("", chat_id=1, message=message)

        self.mock_send_message.assert_awaited_once()
        _, kwargs = self.mock_send_message.call_args
        confirm_btn, change_btn = kwargs["reply_markup"]["inline_keyboard"][0]
        self.assertEqual(confirm_btn["text"], activation_i18n.button("CONFIRM", "zh-Hans"))
        self.assertEqual(change_btn["text"], activation_i18n.button("CHANGE_MEDIA", "zh-Hans"))


class LocalizedCallbackToastTests(H1FTestBase):
    """A4U/A4M confirmation-callback fail-closed toasts (answerCallbackQuery
    text) must render in the session's chosen language once one is known —
    the pre-session-lookup format guards stay English by design (no session
    exists yet at that point), but every guard reached after the session is
    looked up must localize. Covers the 5 call sites flagged in review:
    A4U link-is-None, A4U invalid-session, A4M link-is-None, A4M
    invalid-session, A4M invalid-pending-media."""

    def test_a4u_link_is_none_toast_uses_selected_language(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._select_language_and_activate("tok-u1", "km")
        self._run_message("example.com", chat_id=1)  # -> _ACTIVATION_URL_CONFIRM_STATE
        # Archive the slug out from under the pending confirmation so
        # _lookup_unactivated_url_link now returns None.
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_answer.reset_mock()

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")

        self.mock_answer.assert_awaited_once_with(
            "cbq-a4u", text=activation_i18n.text("CALLBACK_INVALID", "km")
        )

    def test_a4u_invalid_session_toast_uses_selected_language(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        # Stay in URL_INPUT_STATE (never sent a URL) — a Confirm tap here
        # is neither a valid nor a duplicate-safe state.
        self._select_language_and_activate("tok-u1", "id")
        self.mock_answer.reset_mock()

        self._run_a4u_callback(f"{bot_runtime._A4U_CONFIRM_PAYLOAD_PREFIX}tok-u1")

        self.mock_answer.assert_awaited_once_with(
            "cbq-a4u", text=activation_i18n.text("CALLBACK_INVALID", "id")
        )

    def test_a4m_link_is_none_toast_uses_selected_language(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._select_language_and_activate("tok-m1", "zh-Hans")
        self._run_message(
            "", chat_id=1, message={"photo": [{"file_id": "file123", "file_size": 1000}]}
        )  # -> _ACTIVATION_MEDIA_CONFIRM_STATE
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=activation_i18n.text("CALLBACK_INVALID", "zh-Hans")
        )

    def test_a4m_invalid_session_toast_uses_selected_language(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        # Stay in MEDIA_INPUT_STATE (never sent a photo).
        self._select_language_and_activate("tok-m1", "km")
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=activation_i18n.text("CALLBACK_INVALID", "km")
        )

    def test_a4m_invalid_pending_media_toast_uses_selected_language(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._select_language_and_activate("tok-m1", "id")
        self._run_message(
            "", chat_id=1, message={"photo": [{"file_id": "file123", "file_size": 1000}]}
        )  # -> _ACTIVATION_MEDIA_CONFIRM_STATE with valid pending_activation_media
        # Corrupt the pending media so _is_valid_pending_activation_media fails
        # while the session otherwise remains valid.
        bot_runtime._SESSIONS[1]["pending_activation_media"] = {"telegram_file_id": ""}
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=activation_i18n.text("CALLBACK_INVALID", "id")
        )


class LanguageFallbackTests(H1FTestBase):
    def test_missing_session_language_falls_back_to_english(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        # Simulate a session that predates this hotfix: state present, no
        # "language" key at all.
        client = models.BotClient(client_name="Test Client", access_code="ABC123", is_active=True)
        self.db.add(client)
        self.db.commit()
        bot_runtime._SESSIONS[1] = {
            "state": bot_runtime._ACTIVATION_URL_INPUT_STATE,
            "activation_token": "tok-u1",
            "bot_client_id": client.id,
            "content_type": "url",
        }

        self._run_message("not a url!!", chat_id=1)

        self.mock_send_message.assert_awaited_once_with(
            1, activation_i18n.text("URL_INVALID_FORMAT", "en")
        )

    def test_unrecognised_session_language_falls_back_to_english(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        client = models.BotClient(client_name="Test Client", access_code="ABC124", is_active=True)
        self.db.add(client)
        self.db.commit()
        bot_runtime._SESSIONS[1] = {
            "state": bot_runtime._ACTIVATION_URL_INPUT_STATE,
            "activation_token": "tok-u1",
            "bot_client_id": client.id,
            "content_type": "url",
            "language": "fr",  # no longer a supported code
        }

        self._run_message("not a url!!", chat_id=1)

        self.mock_send_message.assert_awaited_once_with(
            1, activation_i18n.text("URL_INVALID_FORMAT", "en")
        )

    def test_activation_text_helper_falls_back_for_unknown_lang(self):
        self.assertEqual(
            activation_i18n.text("URL_RETRY", "not-a-real-lang"),
            activation_i18n.text("URL_RETRY", "en"),
        )
        self.assertEqual(
            activation_i18n.text("URL_RETRY", None),
            activation_i18n.text("URL_RETRY", "en"),
        )

    def test_activation_button_helper_falls_back_for_unknown_lang(self):
        self.assertEqual(
            activation_i18n.button("CONFIRM", "not-a-real-lang"),
            activation_i18n.button("CONFIRM", "en"),
        )

    def test_every_message_key_has_exactly_the_4_supported_languages(self):
        expected_codes = {code for code, _ in activation_i18n.SUPPORTED_LANGUAGES}
        self.assertEqual(expected_codes, {"en", "km", "id", "zh-Hans"})
        for key, translations in activation_i18n.MESSAGES.items():
            if key == "LANGUAGE_PROMPT":
                # Shown before any language is known — English-only by design.
                self.assertEqual(set(translations.keys()), {"en"})
                continue
            with self.subTest(key=key):
                self.assertEqual(set(translations.keys()), expected_codes)

    def test_every_button_key_has_exactly_the_4_supported_languages(self):
        expected_codes = {code for code, _ in activation_i18n.SUPPORTED_LANGUAGES}
        for key, translations in activation_i18n.BUTTONS.items():
            with self.subTest(key=key):
                self.assertEqual(set(translations.keys()), expected_codes)

    def test_callback_invalid_key_reused_for_localized_toasts_not_duplicated(self):
        # This cleanup reuses the pre-existing CALLBACK_INVALID key for the
        # 5 newly-localized A4U/A4M toasts rather than adding a new key —
        # confirm it still carries all 4 languages and matches the English
        # constant bot_runtime.py's pre-session guards still use verbatim.
        self.assertEqual(
            activation_i18n.text("CALLBACK_INVALID", "en"), bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.assertEqual(set(activation_i18n.MESSAGES["CALLBACK_INVALID"].keys()), {"en", "km", "id", "zh-Hans"})


class WebhookLanguageCallbackDispatchTests(unittest.TestCase):
    """Integration test proving the webhook route dispatches "actlang_"
    callback_data to the new H1F handler, without disturbing the existing
    "activate_"/"a4uconfirm_"/etc. dispatch order."""

    def setUp(self):
        from sqlalchemy.pool import StaticPool

        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from database import get_db

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
            "/bot/telegram/webhook",
            json=body,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test-secret"},
        )

    def test_webhook_dispatches_language_selector_callback(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db.commit()
        bot_runtime._SESSIONS[42] = {
            "state": bot_runtime._ACTIVATION_LANGUAGE_SELECT_STATE,
            "activation_token": "tok-u1",
        }

        response = self._post({
            "update_id": 3003,
            "callback_query": {
                "id": "cbq-lang",
                "data": "actlang_id_tok-u1",
                "message": {"chat": {"id": 42}},
                "from": {"id": 777, "username": "buyer1", "first_name": "Ana"},
            },
        })

        self.assertEqual(response.status_code, 200)
        self.mock_answer.assert_awaited_once_with("cbq-lang")
        self.assertEqual(bot_runtime._SESSIONS[42]["language"], "id")
        self.mock_send_message.assert_awaited_once()
        args, _ = self.mock_send_message.call_args
        self.assertEqual(args[1], activation_i18n.text("ENTRY", "id"))

    def test_webhook_still_dispatches_ordinary_activate_callback(self):
        link = models.RedirectLink(slug="u2", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u2", activation_token="tok-u2"))
        self.db.commit()

        response = self._post({
            "update_id": 3004,
            "callback_query": {
                "id": "cbq-act",
                "data": "activate_tok-u2",
                "message": {"chat": {"id": 43}},
                "from": {"id": 888, "username": "buyer2", "first_name": "Bo"},
            },
        })

        self.assertEqual(response.status_code, 200)
        self.mock_answer.assert_awaited_once_with("cbq-act")
        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "888").first()
        self.assertIsNotNone(client)


if __name__ == "__main__":
    unittest.main()
