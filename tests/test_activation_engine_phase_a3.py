"""Regression tests for Activation Engine v1 Phase A3 (Bot Client Creation
and Access Code).

Covers:
  - bot_runtime._resolve_or_create_bot_client_for_telegram (identity
    resolution: reuse/create/inactive/ambiguous)
  - bot_runtime._handle_activation_callback's Phase A3 extension (resolves
    or creates the BotClient and sends the access code)
  - the archived-slug guard added to bot_runtime._lookup_unactivated_record,
    shared by _handle_activation_entry and _handle_activation_callback
  - the webhook route's callback_query dispatch remains idempotent under
    both update_id redelivery and a genuine repeated button press

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message and
bot_runtime._answer_callback_query are patched with AsyncMock everywhere
they're exercised, matching tests/test_activation_engine_phase_a2.py.
"""
import asyncio
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import bot_runtime
import models
from database import Base, get_db


def _make_in_memory_session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return SessionLocal()


class ResolveOrCreateBotClientTests(unittest.TestCase):
    """Unit tests for bot_runtime._resolve_or_create_bot_client_for_telegram."""

    def setUp(self):
        self.db = _make_in_memory_session()

    def tearDown(self):
        self.db.close()

    def test_no_match_creates_exactly_one_active_client(self):
        status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, "1001", "shopper", "Sam", "Lee"
        )

        self.assertEqual(status, "created")
        self.assertIsNotNone(client)
        self.assertTrue(client.is_active)
        self.assertEqual(client.telegram_user_id, "1001")
        self.assertEqual(client.telegram_username, "shopper")
        self.assertEqual(self.db.query(models.BotClient).count(), 1)

    def test_client_name_prefers_first_last_name(self):
        _, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, "1001", "shopper", "Sam", "Lee"
        )
        self.assertEqual(client.client_name, "Sam Lee")

    def test_client_name_falls_back_to_username(self):
        _, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, "1002", "shopper2", None, None
        )
        self.assertEqual(client.client_name, "@shopper2")

    def test_client_name_falls_back_to_telegram_user_id(self):
        _, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, "1003", None, None, None
        )
        self.assertEqual(client.client_name, "Telegram user 1003")

    def test_created_client_access_code_uses_existing_generator(self):
        with patch.object(
            bot_runtime, "_generate_access_code", return_value="ABC123"
        ) as mock_generate:
            status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
                self.db, "1001", "shopper", "Sam", None
            )
        mock_generate.assert_called_once_with(self.db)
        self.assertEqual(status, "created")
        self.assertEqual(client.access_code, "ABC123")

    def test_existing_active_match_is_reused_without_regenerating_code(self):
        existing = models.BotClient(
            client_name="Existing Client", access_code="ZZ9999", telegram_user_id="2001",
            telegram_username="old_name", is_active=True,
        )
        self.db.add(existing)
        self.db.commit()

        with patch.object(bot_runtime, "_generate_access_code") as mock_generate:
            status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
                self.db, "2001", "new_name", "New", "Name"
            )

        mock_generate.assert_not_called()
        self.assertEqual(status, "reused")
        self.assertEqual(client.id, existing.id)
        self.assertEqual(client.access_code, "ZZ9999")
        # A profile change during activation must not rename/modify the client.
        self.assertEqual(client.client_name, "Existing Client")
        self.assertEqual(client.telegram_username, "old_name")
        self.assertEqual(self.db.query(models.BotClient).count(), 1)

    def test_existing_inactive_match_is_rejected_and_not_reactivated(self):
        inactive = models.BotClient(
            client_name="Deactivated Client", access_code="INAC01", telegram_user_id="3001",
            is_active=False,
        )
        self.db.add(inactive)
        self.db.commit()

        status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, "3001", "someone", None, None
        )

        self.assertEqual(status, "inactive")
        self.assertIsNone(client)
        self.db.refresh(inactive)
        self.assertFalse(inactive.is_active)
        self.assertEqual(self.db.query(models.BotClient).count(), 1)

    def test_multiple_matches_fail_closed_as_ambiguous(self):
        self.db.add_all([
            models.BotClient(client_name="Dup 1", access_code="DUP001", telegram_user_id="4001", is_active=True),
            models.BotClient(client_name="Dup 2", access_code="DUP002", telegram_user_id="4001", is_active=True),
        ])
        self.db.commit()

        status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, "4001", "someone", None, None
        )

        self.assertEqual(status, "ambiguous")
        self.assertIsNone(client)
        self.assertEqual(self.db.query(models.BotClient).count(), 2)

    def test_multiple_matches_of_mixed_status_still_ambiguous(self):
        self.db.add_all([
            models.BotClient(client_name="Dup 1", access_code="DUP003", telegram_user_id="4002", is_active=True),
            models.BotClient(client_name="Dup 2", access_code="DUP004", telegram_user_id="4002", is_active=False),
        ])
        self.db.commit()

        status, client = bot_runtime._resolve_or_create_bot_client_for_telegram(
            self.db, "4002", "someone", None, None
        )

        self.assertEqual(status, "ambiguous")
        self.assertIsNone(client)


class HandleActivationCallbackA3Tests(unittest.TestCase):
    """Unit tests for the Phase A3 extension of bot_runtime._handle_activation_callback."""

    def setUp(self):
        self.db = _make_in_memory_session()

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

    def _callback_query(self, data, callback_query_id="cbq1", chat_id=42, from_user=None):
        cq = {
            "id": callback_query_id,
            "data": data,
            "message": {"chat": {"id": chat_id}},
        }
        if from_user is not None:
            cq["from"] = from_user
        return cq

    def _run(self, data, chat_id=42, from_user=None, callback_query_id="cbq1"):
        asyncio.run(
            bot_runtime._handle_activation_callback(
                self._callback_query(data, callback_query_id=callback_query_id, chat_id=chat_id, from_user=from_user),
                self.db,
            )
        )

    # -- creation / access code -------------------------------------------------

    def test_valid_url_activation_creates_one_active_client(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", from_user={"id": 111, "username": "shopper"})

        clients = self.db.query(models.BotClient).all()
        self.assertEqual(len(clients), 1)
        self.assertTrue(clients[0].is_active)
        self.assertEqual(clients[0].telegram_user_id, "111")

    def test_valid_media_activation_creates_one_active_client(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._run("activate_tok-m1", from_user={"id": 112, "username": "shopper2"})

        clients = self.db.query(models.BotClient).all()
        self.assertEqual(len(clients), 1)
        self.assertTrue(clients[0].is_active)

    def test_generated_access_code_is_sent_to_customer(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", chat_id=42, from_user={"id": 113})

        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "113").first()
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACCESS_CODE_READY_TEXT.format(code=client.access_code)
        )

    def test_access_code_uses_existing_generator_path(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        with patch.object(bot_runtime, "_generate_access_code", return_value="FIXED1") as mock_generate:
            self._run("activate_tok-u1", from_user={"id": 114})
        mock_generate.assert_called_once_with(self.db)
        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "114").first()
        self.assertEqual(client.access_code, "FIXED1")

    # -- idempotency / reuse -----------------------------------------------------

    def test_repeated_callback_reuses_same_client_and_code(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", from_user={"id": 115}, callback_query_id="cbq-a")
        first = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "115").first()

        self._run("activate_tok-u1", from_user={"id": 115}, callback_query_id="cbq-b")

        clients = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "115").all()
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0].access_code, first.access_code)

    def test_existing_active_matching_client_is_reused(self):
        existing = models.BotClient(
            client_name="Existing", access_code="EXIST1", telegram_user_id="116", is_active=True,
        )
        self.db.add(existing)
        self.db.commit()
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("activate_tok-u1", from_user={"id": 116})

        self.assertEqual(self.db.query(models.BotClient).count(), 1)
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACCESS_CODE_READY_TEXT.format(code="EXIST1")
        )

    def test_existing_client_access_code_is_not_regenerated(self):
        existing = models.BotClient(
            client_name="Existing", access_code="EXIST2", telegram_user_id="117", is_active=True,
        )
        self.db.add(existing)
        self.db.commit()
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("activate_tok-u1", from_user={"id": 117})

        self.db.refresh(existing)
        self.assertEqual(existing.access_code, "EXIST2")

    def test_existing_inactive_matching_client_is_rejected_no_replacement(self):
        inactive = models.BotClient(
            client_name="Deactivated", access_code="INAC02", telegram_user_id="118", is_active=False,
        )
        self.db.add(inactive)
        self.db.commit()
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("activate_tok-u1", chat_id=42, from_user={"id": 118})

        self.assertEqual(self.db.query(models.BotClient).count(), 1)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_CLIENT_BLOCKED_TEXT)

    def test_multiple_matching_telegram_clients_fail_closed(self):
        self.db.add_all([
            models.BotClient(client_name="Dup 1", access_code="DUP005", telegram_user_id="119", is_active=True),
            models.BotClient(client_name="Dup 2", access_code="DUP006", telegram_user_id="119", is_active=True),
        ])
        self.db.commit()
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("activate_tok-u1", chat_id=42, from_user={"id": 119})

        self.assertEqual(self.db.query(models.BotClient).count(), 2)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_CLIENT_BLOCKED_TEXT)

    # -- rejection: invalid/missing token, identity -----------------------------

    def test_invalid_token_creates_nothing(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_no-such-token", from_user={"id": 120})

        self.assertEqual(self.db.query(models.BotClient).count(), 0)

    def test_missing_malformed_token_creates_nothing(self):
        self._run("activate_", from_user={"id": 121})
        self.assertEqual(self.db.query(models.BotClient).count(), 0)

    def test_missing_telegram_user_id_creates_nothing(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", chat_id=42, from_user=None)

        self.assertEqual(self.db.query(models.BotClient).count(), 0)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_MISSING_IDENTITY_TEXT)

    def test_malformed_telegram_user_id_creates_nothing(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", chat_id=42, from_user={"id": "not-a-number"})

        self.assertEqual(self.db.query(models.BotClient).count(), 0)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_MISSING_IDENTITY_TEXT)

    def test_zero_negative_and_boolean_telegram_user_id_creates_nothing(self):
        # bool is a subclass of int in Python — 0/negative/True/False must
        # all be rejected by the same isinstance(..., bool)/<= 0 guard.
        self._make_link_and_record("u1", "url", "tok-u1")
        malformed_ids = {"zero": 0, "negative": -1, "true": True, "false": False}

        for label, bad_id in malformed_ids.items():
            with self.subTest(telegram_user_id=label):
                self.mock_send_message.reset_mock()
                bot_runtime._SESSIONS.pop(42, None)
                self._run("activate_tok-u1", chat_id=42, from_user={"id": bad_id})

                self.assertEqual(self.db.query(models.BotClient).count(), 0)
                self.assertNotIn(42, bot_runtime._SESSIONS)
                self.mock_send_message.assert_awaited_once_with(
                    42, bot_runtime._ACTIVATION_MISSING_IDENTITY_TEXT
                )

    def test_page_slug_cannot_enter_a3(self):
        # page slugs never receive an ActivationRecord (enforced by
        # models.create_activation_record_for_slug in Phase A1) — there is no
        # legitimate token for a page slug. _lookup_unactivated_record still
        # fails closed on any token that doesn't match a real record.
        self.db.add(models.RedirectLink(slug="p1", destination_url="https://example.com/p1", content_type="page"))
        self.db.commit()

        self._run("activate_forged-token", chat_id=42, from_user={"id": 122})

        self.assertEqual(self.db.query(models.BotClient).count(), 0)

    def test_archived_slug_rejected_at_callback(self):
        self._make_link_and_record("u1", "url", "tok-u1", is_archived=True)

        self._run("activate_tok-u1", chat_id=42, from_user={"id": 123})

        self.assertEqual(self.db.query(models.BotClient).count(), 0)
        self.mock_send_message.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with("cbq1", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT)

    def test_archived_slug_rejected_at_entry(self):
        self._make_link_and_record("u1", "url", "tok-u1", is_archived=True)

        asyncio.run(bot_runtime._handle_activation_entry(42, "activate_tok-u1", self.db))

        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_missing_slug_is_rejected(self):
        # No FK enforcement in this SQLite schema (documented existing
        # behaviour) — construct a record whose slug has no RedirectLink row.
        self.db.add(models.ActivationRecord(slug="ghost", activation_token="tok-ghost"))
        self.db.commit()

        self._run("activate_tok-ghost", chat_id=42, from_user={"id": 124})

        self.assertEqual(self.db.query(models.BotClient).count(), 0)

    def test_activated_record_cannot_restart_activation(self):
        self._make_link_and_record("u1", "url", "tok-u1", status="activated")

        self._run("activate_tok-u1", chat_id=42, from_user={"id": 125})

        self.assertEqual(self.db.query(models.BotClient).count(), 0)

    # -- session continuation ----------------------------------------------------

    def test_session_stores_token_client_id_and_content_type_for_url(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", chat_id=77, from_user={"id": 126})

        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "126").first()
        session = bot_runtime._SESSIONS[77]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["activation_token"], "tok-u1")
        self.assertEqual(session["bot_client_id"], client.id)
        self.assertEqual(session["content_type"], "url")

    def test_session_stores_content_type_for_media_without_asking(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._run("activate_tok-m1", chat_id=78, from_user={"id": 127})

        session = bot_runtime._SESSIONS[78]
        self.assertEqual(session["content_type"], "media")
        # The bot never asks the customer to choose/confirm content type.
        sent_text = self.mock_send_message.await_args.args[1]
        self.assertNotIn("url", sent_text.lower())
        self.assertNotIn("media", sent_text.lower())

    def test_inactive_rejection_clears_pending_session(self):
        bot_runtime._SESSIONS[42] = {"state": "awaiting_activation_confirmation", "activation_token": "tok-u1"}
        inactive = models.BotClient(
            client_name="Deactivated", access_code="INAC03", telegram_user_id="128", is_active=False,
        )
        self.db.add(inactive)
        self.db.commit()
        self._make_link_and_record("u1", "url", "tok-u1")

        self._run("activate_tok-u1", chat_id=42, from_user={"id": 128})

        self.assertNotIn(42, bot_runtime._SESSIONS)

    # -- activation-record / content invariants ----------------------------------

    def test_activation_status_remains_unactivated(self):
        _, record = self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", from_user={"id": 129})

        self.db.refresh(record)
        self.assertEqual(record.activation_status, "unactivated")

    def test_activated_at_remains_null(self):
        _, record = self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", from_user={"id": 130})

        self.db.refresh(record)
        self.assertIsNone(record.activated_at)

    def test_owner_client_id_remains_null(self):
        _, record = self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", from_user={"id": 131})

        self.db.refresh(record)
        self.assertIsNone(record.owner_client_id)

    def test_url_destination_remains_unchanged(self):
        link, _ = self._make_link_and_record("u1", "url", "tok-u1")
        self._run("activate_tok-u1", from_user={"id": 132})

        self.db.refresh(link)
        self.assertEqual(link.destination_url, "https://example.com")

    def test_existing_media_remains_unchanged(self):
        link, _ = self._make_link_and_record("m1", "media", "tok-m1")
        asset = models.MediaAsset(
            media_type="image", storage_key="k1", public_url="https://media.shadz.io/k1",
            original_filename="a.jpg", mime_type="image/jpeg", file_size=100,
        )
        self.db.add(asset)
        self.db.flush()
        slug_media = models.SlugMedia(slug="m1", media_asset_id=asset.id, is_active=True)
        self.db.add(slug_media)
        self.db.commit()

        self._run("activate_tok-m1", from_user={"id": 133})

        self.db.refresh(slug_media)
        self.assertTrue(slug_media.is_active)
        self.assertEqual(self.db.query(models.SlugMedia).count(), 1)
        self.assertEqual(self.db.query(models.MediaAsset).count(), 1)

    def test_database_failure_rolls_back_and_leaves_no_session(self):
        self._make_link_and_record("u1", "url", "tok-u1")

        with patch.object(self.db, "commit", side_effect=Exception("boom")):
            self._run("activate_tok-u1", chat_id=42, from_user={"id": 134})

        self.assertEqual(self.db.query(models.BotClient).count(), 0)
        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_CLIENT_BLOCKED_TEXT)


class WebhookCallbackIdempotencyTests(unittest.TestCase):
    """Integration test proving webhook update_id dedup still holds under A3,
    and that a genuine second button press (new update_id) is independently
    idempotent via the BotClient identity lookup rather than update_id dedup.
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

    def _callback_body(self, update_id, callback_query_id):
        return {
            "update_id": update_id,
            "callback_query": {
                "id": callback_query_id,
                "data": "activate_tok-u1",
                "message": {"chat": {"id": 42}},
                "from": {"id": 900, "username": "shopper"},
            },
        }

    def test_same_update_id_remains_deduplicated(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db.commit()

        body = self._callback_body(3001, "cbq-a")
        self._post(body)
        self._post(body)

        self.assertEqual(self.mock_answer.await_count, 1)
        self.assertEqual(self.db.query(models.BotClient).count(), 1)

    def test_genuine_repeat_tap_new_update_id_still_reuses_client(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db.commit()

        self._post(self._callback_body(4001, "cbq-b"))
        self._post(self._callback_body(4002, "cbq-c"))

        self.assertEqual(self.mock_answer.await_count, 2)
        self.assertEqual(self.db.query(models.BotClient).count(), 1)


if __name__ == "__main__":
    unittest.main()
