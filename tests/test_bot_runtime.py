"""Regression tests for the Phase 4M Telegram Bot stale-content-type fix.

Covers only the awaiting_confirmation (url) and awaiting_media_upload (media)
state handlers in bot_runtime.py. Uses an isolated in-memory SQLite database —
never touches the real shadz.db. No network calls: TELEGRAM_BOT_TOKEN is left
unset, so _send_message logs and returns without hitting Telegram.
"""
import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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

    def tearDown(self):
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


if __name__ == "__main__":
    unittest.main()
