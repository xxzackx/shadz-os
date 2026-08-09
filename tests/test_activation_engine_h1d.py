"""Regression tests for Activation Engine v1 — Production Hotfix H1D
(Telegram URL Auto Normalization).

Covers bot_runtime._normalize_telegram_destination_url directly, plus its
wiring into both Telegram destination-URL entry points:
  - the Activation Engine A4U flow (_ACTIVATION_URL_INPUT_STATE)
  - the T1B self-service "awaiting_new_url" flow

Before H1D, both flows rejected any input that didn't literally start with
"http://" or "https://". H1D adds normalization: whitespace is trimmed,
an existing http(s) scheme is detected case-insensitively and preserved
verbatim, and "https://" is prepended when no scheme is present and the
input looks like a domain (contains a dot) — so plain input like
"google.com" now works. Non-http(s) schemes (javascript:, file:, ftp:),
missing/empty hostnames, blank input, and scheme-less junk text (no dot)
are still rejected. The pre-existing _is_blocked_destination_url guard
(SHADZ/internal/loopback hosts) is unchanged and still runs on the
normalized result.

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message is patched with
AsyncMock, matching the existing Phase A4U / management-flow test files.
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


class NormalizeTelegramDestinationUrlTests(unittest.TestCase):
    """Direct unit tests for the normalization helper, independent of
    either flow that calls it."""

    def test_bare_domain_gets_https_prepended(self):
        self.assertEqual(
            bot_runtime._normalize_telegram_destination_url("google.com"),
            "https://google.com",
        )

    def test_bare_domain_with_path_gets_https_prepended(self):
        self.assertEqual(
            bot_runtime._normalize_telegram_destination_url("  example.com/path  "),
            "https://example.com/path",
        )

    def test_explicit_http_is_preserved(self):
        self.assertEqual(
            bot_runtime._normalize_telegram_destination_url("http://example.com"),
            "http://example.com",
        )

    def test_explicit_uppercase_https_is_not_double_prefixed(self):
        result = bot_runtime._normalize_telegram_destination_url("HTTPS://example.com")
        self.assertEqual(result, "HTTPS://example.com")
        self.assertTrue(result.lower().startswith("https://"))
        self.assertFalse(result.lower().startswith("https://https://"))

    def test_blank_input_is_rejected(self):
        self.assertIsNone(bot_runtime._normalize_telegram_destination_url(""))
        self.assertIsNone(bot_runtime._normalize_telegram_destination_url("   "))

    def test_javascript_scheme_is_rejected(self):
        self.assertIsNone(
            bot_runtime._normalize_telegram_destination_url("javascript:alert(1)")
        )

    def test_file_scheme_is_rejected(self):
        self.assertIsNone(
            bot_runtime._normalize_telegram_destination_url("file:///etc/passwd")
        )

    def test_ftp_scheme_is_rejected(self):
        self.assertIsNone(
            bot_runtime._normalize_telegram_destination_url("ftp://example.com")
        )

    def test_scheme_less_junk_text_without_dot_is_rejected(self):
        self.assertIsNone(bot_runtime._normalize_telegram_destination_url("not-a-url"))

    def test_missing_hostname_is_rejected(self):
        self.assertIsNone(bot_runtime._normalize_telegram_destination_url("https://"))

    def test_scheme_less_host_with_port_is_normalized(self):
        self.assertEqual(
            bot_runtime._normalize_telegram_destination_url("example.com:8080/path"),
            "https://example.com:8080/path",
        )

    def test_explicit_https_with_port_and_mixed_case_is_preserved(self):
        self.assertEqual(
            bot_runtime._normalize_telegram_destination_url("HTTPS://EXAMPLE.COM:8443/Path"),
            "HTTPS://EXAMPLE.COM:8443/Path",
        )

    def test_explicit_scheme_with_invalid_port_is_rejected(self):
        self.assertIsNone(
            bot_runtime._normalize_telegram_destination_url("https://example.com:abc")
        )

    def test_scheme_less_host_with_invalid_port_is_rejected(self):
        self.assertIsNone(
            bot_runtime._normalize_telegram_destination_url("example.com:abc")
        )


class A4uUrlNormalizationTests(unittest.TestCase):
    """Integration coverage: the Activation Engine A4U URL-input state
    normalizes input before showing it for confirmation."""

    def setUp(self):
        self.db = _make_in_memory_session()
        bot_runtime._SESSIONS.clear()
        self._send_message_patcher = patch.object(
            bot_runtime, "_send_message", new_callable=AsyncMock
        )
        self.mock_send_message = self._send_message_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    def _run_message(self, chat_id, text):
        asyncio.run(
            bot_runtime._handle_message(chat_id, text, {"id": 999}, self.db, {"text": text})
        )

    def _run_callback(self, data, chat_id=42, from_user=None):
        cq = {"id": "cbq1", "data": data, "message": {"chat": {"id": chat_id}}}
        if from_user is not None:
            cq["from"] = from_user
        asyncio.run(bot_runtime._handle_activation_callback(cq, self.db))

    def _activate_url_slug(self, slug="u1", token="tok-u1", chat_id=42, telegram_id=201):
        link = models.RedirectLink(slug=slug, destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        record = models.ActivationRecord(slug=slug, activation_token=token, activation_status="unactivated")
        self.db.add(record)
        self.db.commit()
        self._run_callback(f"activate_{token}", chat_id=chat_id, from_user={"id": telegram_id})
        self.mock_send_message.reset_mock()

    def test_bare_domain_is_normalized_before_confirmation(self):
        self._activate_url_slug()

        self._run_message(42, "google.com")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_CONFIRM_STATE)
        self.assertEqual(session["pending_url"], "https://google.com")
        self.mock_send_message.assert_awaited_once_with(
            42,
            bot_runtime._ACTIVATION_URL_CONFIRM_PROMPT_TEXT.format(url="https://google.com"),
            reply_markup=bot_runtime._a4u_confirmation_markup("tok-u1"),
        )

    def test_confirming_normalized_url_saves_normalized_value(self):
        self._activate_url_slug()

        self._run_message(42, "  example.com/path  ")
        self._run_message(42, "YES")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://example.com/path")

    def test_blocked_host_check_still_applies_to_normalized_url(self):
        self._activate_url_slug()

        self._run_message(42, "shadz.io/some-slug")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_URL_BLOCKED_TEXT)


class SelfServiceUrlNormalizationTests(unittest.TestCase):
    """Integration coverage: the T1B self-service awaiting_new_url flow
    normalizes input before showing it for confirmation."""

    def setUp(self):
        self.db = _make_in_memory_session()
        bot_runtime._SESSIONS.clear()
        self._send_message_patcher = patch.object(
            bot_runtime, "_send_message", new_callable=AsyncMock
        )
        self.mock_send_message = self._send_message_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self.db.close()
        bot_runtime._SESSIONS.clear()

    def _run_message(self, chat_id, text):
        asyncio.run(
            bot_runtime._handle_message(chat_id, text, {"id": 999}, self.db, {"text": text})
        )

    def test_bare_domain_is_normalized_before_confirmation(self):
        client = models.BotClient(client_name="Test Client", access_code="ABC123", is_active=True)
        self.db.add(client)
        self.db.commit()

        link = models.RedirectLink(slug="u1", destination_url="https://old.example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug="u1"))
        self.db.commit()

        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_new_url",
            "bot_client_id": client.id,
            "slugs": [{"slug": "u1", "content_type": "url"}],
            "selected_slug": "u1",
        }

        self._run_message(42, "google.com")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_confirmation")
        self.assertEqual(session["pending_value"], "https://google.com")
