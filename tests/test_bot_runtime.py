"""Regression tests for bot_runtime.py.

Covers:
  - the Phase 4M stale-content-type fix (awaiting_confirmation / url and
    awaiting_media_upload / media state handlers)
  - the Phase 4N secret-safe logging fix in _send_message and
    _download_telegram_file

Network isolation: bot_runtime._send_message is patched with an AsyncMock for
every test in this file, so no real httpx.AsyncClient is ever constructed by
the state-machine tests regardless of whether TELEGRAM_BOT_TOKEN is unset, a
fake value, or a real value in the environment. The dedicated logging tests
below patch httpx.AsyncClient itself to simulate Telegram HTTP failures
without any real network access. Uses an isolated in-memory SQLite database —
never touches the real shadz.db.
"""
import asyncio
import logging
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
from database import Base
import bot_runtime


class BotRuntimeStaleTypeTests(unittest.TestCase):
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

    def _make_client_and_link(self, content_type, slug, destination_url=""):
        client = models.BotClient(client_name="Test Client", access_code="AB12CD", is_active=True)
        self.db.add(client)
        link = models.RedirectLink(
            slug=slug,
            destination_url=destination_url,
            content_type=content_type,
        )
        self.db.add(link)
        self.db.commit()
        self.db.refresh(client)
        self.db.refresh(link)
        return client, link

    def _reload_link(self, slug):
        return self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()

    # ── URL confirmation ────────────────────────────────────────────────────

    def test_url_confirmation_succeeds_when_still_url(self):
        client, link = self._make_client_and_link(
            "url", "url-abc123", destination_url="https://old.example.com"
        )
        chat_id = 1
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_confirmation",
            "bot_client_id": client.id,
            "slugs": [{"slug": link.slug, "content_type": "url", "notes": None}],
            "selected_slug": link.slug,
            "pending_value": "https://new.example.com",
        }
        asyncio.run(bot_runtime._handle_message(chat_id, "YES", {}, self.db, {}))
        refreshed = self._reload_link(link.slug)
        self.assertEqual(refreshed.destination_url, "https://new.example.com")

        # Confirm now also returns to the correct resting state afterward
        # (a single assigned slug here, so a fresh access-code prompt) —
        # the typed path is unified with the button path, which always
        # follows its completion message with that return.
        self.assertEqual(self.mock_send_message.await_count, 2)
        completion_calls = [
            call for call in self.mock_send_message.await_args_list
            if "https://new.example.com" in call.args[1]
        ]
        self.assertEqual(len(completion_calls), 1)
        self.assertEqual(completion_calls[0].args[0], chat_id)

    def test_url_confirmation_rejected_when_slug_became_media(self):
        client, link = self._make_client_and_link(
            "url", "url-def456", destination_url="https://old.example.com"
        )
        # Simulate an admin converting the slug to media mid-session, after
        # the customer already cached content_type="url" at slug-selection time.
        link.content_type = "media"
        self.db.commit()

        chat_id = 2
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_confirmation",
            "bot_client_id": client.id,
            "slugs": [{"slug": link.slug, "content_type": "url", "notes": None}],
            "selected_slug": link.slug,
            "pending_value": "https://new.example.com",
        }
        asyncio.run(bot_runtime._handle_message(chat_id, "YES", {}, self.db, {}))
        refreshed = self._reload_link(link.slug)
        self.assertEqual(refreshed.destination_url, "https://old.example.com")
        self.assertEqual(refreshed.content_type, "media")

        # The rejection is also followed by a return to the correct
        # resting state (single assigned slug here, so a fresh
        # access-code prompt) — same unified behaviour as Confirm.
        self.assertEqual(self.mock_send_message.await_count, 2)
        rejection_calls = [
            call for call in self.mock_send_message.await_args_list
            if "no longer available" in call.args[1]
        ]
        self.assertEqual(len(rejection_calls), 1)
        self.assertEqual(rejection_calls[0].args[0], chat_id)

    # ── Media upload — existing guard must remain intact ───────────────────

    def test_media_upload_still_rejected_when_slug_no_longer_media(self):
        client, link = self._make_client_and_link("media", "media-xyz789")
        # Simulate an admin converting the slug away from media mid-session.
        link.content_type = "url"
        self.db.commit()

        chat_id = 3
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_media_upload",
            "bot_client_id": client.id,
            "slugs": [{"slug": link.slug, "content_type": "media", "notes": None}],
            "selected_slug": link.slug,
        }
        message = {
            "document": {
                "file_id": "abc123",
                "mime_type": "image/png",
                "file_size": 100,
                "file_name": "x.png",
            }
        }
        asyncio.run(bot_runtime._handle_message(chat_id, "", {}, self.db, message))
        count = (
            self.db.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == link.slug)
            .count()
        )
        self.assertEqual(count, 0)

        self.mock_send_message.assert_awaited_once()
        called_chat_id, called_text = self.mock_send_message.await_args.args
        self.assertEqual(called_chat_id, chat_id)
        self.assertIn("no longer available", called_text)

    def test_media_upload_state_still_prompts_on_unsupported_message(self):
        client, link = self._make_client_and_link("media", "media-uvw111")
        chat_id = 4
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_media_upload",
            "bot_client_id": client.id,
            "slugs": [{"slug": link.slug, "content_type": "media", "notes": None}],
            "selected_slug": link.slug,
        }
        # Plain text carries no supported media field — existing behaviour is
        # to re-prompt without touching the DB, not to reject the slug itself.
        asyncio.run(bot_runtime._handle_message(chat_id, "hello", {}, self.db, {"text": "hello"}))
        count = (
            self.db.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == link.slug)
            .count()
        )
        self.assertEqual(count, 0)
        self.assertEqual(bot_runtime._SESSIONS[chat_id]["state"], "awaiting_media_upload")

        self.mock_send_message.assert_awaited_once()
        called_chat_id, _called_text = self.mock_send_message.await_args.args
        self.assertEqual(called_chat_id, chat_id)


# ── Phase 4N — secret-safe logging ──────────────────────────────────────────

_FAKE_TOKEN = "123456:FAKE-TOKEN-DO-NOT-USE-abcdefgh"


def _make_401_response(url):
    request = httpx.Request("POST", url)
    response = httpx.Response(401, request=request, json={"ok": False, "description": "Unauthorized"})
    return response


class SendMessageLoggingTests(unittest.TestCase):
    """Exercises the real _send_message body (not mocked) against a mocked
    httpx.AsyncClient, so no real network call is possible while still
    covering the actual sanitization logic."""

    def setUp(self):
        self._token_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": _FAKE_TOKEN})
        self._token_patcher.start()

    def tearDown(self):
        self._token_patcher.stop()

    def test_http_status_error_logs_safely_and_does_not_raise(self):
        url = bot_runtime._TELEGRAM_API_BASE.format(token=_FAKE_TOKEN) + "/sendMessage"
        response = _make_401_response(url)

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.post = AsyncMock(return_value=response)

        with patch.object(httpx, "AsyncClient", return_value=mock_client) as mock_ctor:
            with self.assertLogs("bot_runtime", level="ERROR") as captured:
                asyncio.run(bot_runtime._send_message(42, "hello"))  # must not raise

        mock_client.post.assert_awaited_once()
        mock_ctor.assert_called_once()

        log_output = "\n".join(captured.output)
        self.assertIn("401", log_output)
        self.assertNotIn(_FAKE_TOKEN, log_output)
        self.assertNotIn(f"/bot{_FAKE_TOKEN}/", log_output)
        self.assertNotIn("api.telegram.org", log_output)

    def test_non_http_exception_logs_exception_class_only(self):
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.post = AsyncMock(
            side_effect=httpx.ConnectTimeout(
                "connection timed out",
                request=httpx.Request(
                    "POST", f"https://api.telegram.org/bot{_FAKE_TOKEN}/sendMessage"
                ),
            )
        )

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            with self.assertLogs("bot_runtime", level="ERROR") as captured:
                asyncio.run(bot_runtime._send_message(42, "hello"))  # must not raise

        log_output = "\n".join(captured.output)
        self.assertIn("ConnectTimeout", log_output)
        self.assertNotIn(_FAKE_TOKEN, log_output)
        self.assertNotIn("api.telegram.org", log_output)


class DownloadTelegramFileLoggingTests(unittest.TestCase):
    """Exercises the real _download_telegram_file body against a mocked
    httpx.AsyncClient — no real network access."""

    def setUp(self):
        self._token_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": _FAKE_TOKEN})
        self._token_patcher.start()

    def tearDown(self):
        self._token_patcher.stop()

    def _mock_client(self, get_side_effect_or_responses):
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.get = AsyncMock(side_effect=get_side_effect_or_responses)
        return mock_client

    def test_get_file_http_error_raises_sanitized_exception(self):
        get_file_url = bot_runtime._TELEGRAM_API_BASE.format(token=_FAKE_TOKEN) + "/getFile"
        response = _make_401_response(get_file_url)
        mock_client = self._mock_client([response])

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(bot_runtime._download_telegram_file("file123"))

        message = str(ctx.exception)
        self.assertIn("getFile", message)
        self.assertIn("401", message)
        self.assertNotIn(_FAKE_TOKEN, message)
        self.assertNotIn("api.telegram.org", message)
        self.assertIsNone(ctx.exception.__cause__)

    def test_file_download_http_error_raises_sanitized_exception(self):
        get_file_url = bot_runtime._TELEGRAM_API_BASE.format(token=_FAKE_TOKEN) + "/getFile"
        ok_request = httpx.Request("GET", get_file_url)
        ok_response = httpx.Response(
            200,
            request=ok_request,
            json={"ok": True, "result": {"file_path": "documents/file_123.png"}},
        )

        download_url = f"https://api.telegram.org/file/bot{_FAKE_TOKEN}/documents/file_123.png"
        error_response = _make_401_response(download_url)

        mock_client = self._mock_client([ok_response, error_response])

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(bot_runtime._download_telegram_file("file123"))

        message = str(ctx.exception)
        self.assertIn("download", message)
        self.assertIn("401", message)
        self.assertNotIn(_FAKE_TOKEN, message)
        self.assertNotIn("api.telegram.org", message)
        self.assertIsNone(ctx.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
