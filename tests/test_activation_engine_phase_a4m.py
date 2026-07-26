"""Regression tests for Activation Engine v1 Phase A4M (Media Content Setup).

Phase A4M performs ZERO persistent media storage — it never downloads from
Telegram, never uploads to R2, and never creates a MediaAsset or SlugMedia
row. It only validates Telegram's own message metadata and holds it as a
plain dict, session["pending_activation_media"] /
session["confirmed_activation_media"], entirely in memory. Phase A5 (not
yet implemented) owns the actual download/upload/MediaAsset-creation/
slug-attachment sequence.

Covers:
  - a media slug's Phase A3 callback continues into the media-input state
    and sends a prompt right after the access code
  - a url slug never enters any A4M state
  - valid supported media (photo/document/video/GIF) is validated by
    metadata alone and stored as pending_activation_media — no Telegram
    download, no R2 upload, no MediaAsset/SlugMedia row
  - unsupported text/content is rejected without leaving the state or
    creating any pending data
  - the confirmation prompt shows an inline "Confirm" / "Change Media"
    keyboard (no typed fallback — button-only, unlike A4U)
  - Confirm re-validates ActivationRecord/RedirectLink from DB truth, never
    activates or assigns ownership, performs zero DB/R2 writes, and moves
    pending_activation_media to confirmed_activation_media for Phase A5
  - Change Media revalidates DB state and discards the in-memory dicts —
    there is nothing to clean up in R2 or the DB since nothing was ever
    persisted
  - duplicate Confirm/Change Media callbacks are idempotent and revalidate
    DB state
  - archived/already-activated/wrong-type/missing-record/missing-pending-
    media sessions fail closed
  - unrelated text during confirmation does not change state or corrupt
    the session
  - /start abandoning a pending upload leaves zero MediaAsset rows

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message and
_answer_callback_query are patched everywhere they're exercised.
_download_telegram_file and _upload_bytes_to_r2 are also patched, purely
to prove by assertion that A4M never calls them — matching the existing
Phase A4U test file's patching style.
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


class ActivationMediaSetupTests(unittest.TestCase):
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
        # Patched purely so tests can assert these are NEVER called by A4M —
        # Phase A4M must perform zero persistent media storage.
        self._download_patcher = patch.object(
            bot_runtime, "_download_telegram_file", new_callable=AsyncMock
        )
        self.mock_download = self._download_patcher.start()
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

    def _run_message(self, chat_id, text=None, message=None):
        message = message if message is not None else {"text": text}
        asyncio.run(
            bot_runtime._handle_message(chat_id, text or "", {"id": 999}, self.db, message)
        )

    def _run_a4m_callback(self, data, chat_id=42, callback_query_id="cbq-a4m"):
        cq = {"id": callback_query_id, "data": data, "message": {"chat": {"id": chat_id}}}
        asyncio.run(bot_runtime._handle_a4m_confirmation_callback(cq, self.db))

    def _photo_message(self, file_id="file123", file_size=1000):
        return {"photo": [{"file_id": file_id, "file_size": file_size}]}

    def _activate_media_slug(self, slug="m1", token="tok-m1", chat_id=42, telegram_id=201):
        """Drive a media slug through A3 into the A4M media-input state."""
        self._make_link_and_record(slug, "media", token)
        self._run_callback(f"activate_{token}", chat_id=chat_id, from_user={"id": telegram_id})
        self.mock_send_message.reset_mock()

    def _send_photo(self, chat_id=42, file_id="file123", file_size=1000):
        self._run_message(chat_id, message=self._photo_message(file_id, file_size))

    def _seed_confirm_state_with_pending(self, pending, slug, token, chat_id=42):
        """Drive a fresh media slug into _ACTIVATION_MEDIA_CONFIRM_STATE and
        overwrite pending_activation_media with an arbitrary (possibly
        invalid/forged) dict — used to exercise Confirm-time validation
        directly, independent of whatever the input branch would normally
        produce."""
        self._activate_media_slug(slug, token, chat_id=chat_id)
        session = bot_runtime._SESSIONS[chat_id]
        session["state"] = bot_runtime._ACTIVATION_MEDIA_CONFIRM_STATE
        session["pending_activation_media"] = pending
        return session

    # -- entering the media-input state ------------------------------------

    def test_eligible_media_slug_enters_media_input_state(self):
        self._make_link_and_record("m1", "media", "tok-m1")
        self._run_callback("activate_tok-m1", from_user={"id": 201})

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.mock_send_message.assert_any_await(42, bot_runtime._ACTIVATION_MEDIA_PROMPT_TEXT)

    def test_url_slug_does_not_enter_a4m(self):
        self._make_link_and_record("u1", "url", "tok-u1")
        self._run_callback("activate_tok-u1", from_user={"id": 202})

        session = bot_runtime._SESSIONS[42]
        self.assertNotEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)

    # -- valid media: metadata-only validation, zero persistence -------------

    def test_valid_media_stores_pending_activation_media(self):
        self._activate_media_slug()

        self._send_photo(file_id="file123", file_size=1000)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_CONFIRM_STATE)
        self.assertIn("pending_activation_media", session)

    def test_pending_activation_media_has_correct_metadata(self):
        self._activate_media_slug()

        self._send_photo(file_id="file123", file_size=1000)

        pending = bot_runtime._SESSIONS[42]["pending_activation_media"]
        self.assertEqual(pending["telegram_file_id"], "file123")
        self.assertEqual(pending["media_type"], "image")
        self.assertEqual(pending["mime_type"], "image/jpeg")
        self.assertEqual(pending["file_size"], 1000)
        # Telegram photos never carry a file_name — the existing
        # _default_filename fallback convention (shared with T1C) applies.
        self.assertTrue(pending["original_filename"])

    def test_valid_document_media_has_correct_metadata(self):
        self._activate_media_slug()

        self._run_message(42, message={
            "document": {"file_id": "doc1", "mime_type": "image/png", "file_size": 2000, "file_name": "a.png"}
        })

        pending = bot_runtime._SESSIONS[42]["pending_activation_media"]
        self.assertEqual(pending["telegram_file_id"], "doc1")
        self.assertEqual(pending["media_type"], "image")
        self.assertEqual(pending["mime_type"], "image/png")
        self.assertEqual(pending["file_size"], 2000)
        self.assertEqual(pending["original_filename"], "a.png")

    def test_valid_media_never_calls_telegram_download(self):
        self._activate_media_slug()

        self._send_photo()

        self.mock_download.assert_not_awaited()

    def test_valid_media_never_calls_r2_upload(self):
        self._activate_media_slug()

        self._send_photo()

        self.mock_upload.assert_not_called()

    def test_valid_media_creates_no_media_asset_row(self):
        self._activate_media_slug()

        self._send_photo()

        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)

    def test_valid_media_creates_no_slug_media_row(self):
        self._activate_media_slug()

        self._send_photo()

        self.assertEqual(self.db.query(models.SlugMedia).count(), 0)

    def test_confirmation_prompt_includes_confirm_and_change_inline_actions(self):
        self._activate_media_slug("m1", "tok-m1")

        self._send_photo()

        call = self.mock_send_message.await_args
        markup = call.kwargs["reply_markup"]
        buttons = markup["inline_keyboard"][0]
        self.assertEqual(len(buttons), 2)
        self.assertEqual(buttons[0]["text"], "Confirm")
        self.assertEqual(buttons[0]["callback_data"], f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")
        self.assertEqual(buttons[1]["text"], "Change Media")
        self.assertEqual(buttons[1]["callback_data"], f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1")

    # -- unsupported input stays retryable, creates no pending data ---------

    def test_unsupported_text_remains_retryable(self):
        self._activate_media_slug()

        self._run_message(42, "not a file")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACTIVATION_MEDIA_UNSUPPORTED_TEXT
        )
        self.assertNotIn("pending_activation_media", session)

    def test_unsupported_mime_type_creates_no_pending_data(self):
        self._activate_media_slug()

        self._run_message(42, message={
            "document": {"file_id": "doc1", "mime_type": "application/zip", "file_size": 10}
        })

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.assertNotIn("pending_activation_media", session)
        self.mock_download.assert_not_awaited()

    def test_oversized_media_is_rejected_without_download(self):
        self._activate_media_slug()

        self._run_message(42, message={
            "photo": [{"file_id": "big1", "file_size": 50 * 1024 * 1024}]
        })

        self.mock_download.assert_not_awaited()
        session = bot_runtime._SESSIONS[42]
        self.assertNotIn("pending_activation_media", session)

    def test_invalid_reported_sizes_are_rejected_at_input(self):
        cases = {
            "negative": -1,
            "zero": 0,
            "boolean_true": True,
            "boolean_false": False,
            "non_integer_float": 12.5,
            "non_integer_string": "1000",
        }
        for label, bad_size in cases.items():
            with self.subTest(reported_size=label):
                self._activate_media_slug(f"m-{label}", f"tok-{label}")

                self._run_message(42, message={
                    "photo": [{"file_id": f"file-{label}", "file_size": bad_size}]
                })

                self.mock_download.assert_not_awaited()
                session = bot_runtime._SESSIONS[42]
                self.assertNotIn("pending_activation_media", session)
                self.mock_send_message.reset_mock()
                self.mock_download.reset_mock()

    def test_none_reported_size_remains_accepted(self):
        self._activate_media_slug()

        self._run_message(42, message={"photo": [{"file_id": "file123"}]})

        session = bot_runtime._SESSIONS[42]
        self.assertIn("pending_activation_media", session)
        self.assertIsNone(session["pending_activation_media"]["file_size"])

    def test_unsupported_input_creates_no_partial_data(self):
        self._activate_media_slug("m1", "tok-m1")
        self._run_message(42, "not a file")

        record_row = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record_row.activation_status, "unactivated")
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)
        session = bot_runtime._SESSIONS[42]
        self.assertNotIn("pending_activation_media", session)

    # -- confirmation: Confirm inline callback --------------------------------

    def test_confirm_callback_moves_pending_to_confirmed(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo(file_id="file123")
        pending = dict(bot_runtime._SESSIONS[42]["pending_activation_media"])
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(
            f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-1"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["confirmed_activation_media"], pending)
        self.mock_answer.assert_awaited_once_with("cbq-1")
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_MEDIA_SAVED_TEXT)

    def test_confirm_callback_removes_pending_key(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        session = bot_runtime._SESSIONS[42]
        self.assertNotIn("pending_activation_media", session)

    def test_confirm_callback_performs_zero_db_media_writes(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(link.content_type, "media")
        self.assertEqual(record.activation_status, "unactivated")
        self.assertIsNone(record.activated_at)
        self.assertIsNone(record.owner_client_id)
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        self.assertEqual(self.db.query(models.SlugMedia).count(), 0)
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)
        self.mock_download.assert_not_awaited()
        self.mock_upload.assert_not_called()

    def test_confirm_callback_fails_closed_on_archived_slug(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_confirm_callback_fails_closed_on_activated_record(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        record.activation_status = "activated"
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        self.db.refresh(record)
        self.assertIsNone(record.owner_client_id)
        self.assertIsNone(record.activated_at)

    def test_confirm_callback_fails_closed_when_content_type_becomes_url(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.content_type = "url"
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "unactivated")

    def test_confirm_callback_fails_closed_on_missing_activation_record(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.db.delete(record)
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_confirm_callback_fails_closed_when_pending_media_missing(self):
        self._activate_media_slug("m1", "tok-m1")
        # Forge a session sitting in the confirmation state without ever
        # having sent media — must never happen through the normal flow,
        # but the handler must still fail closed defensively.
        bot_runtime._SESSIONS[42] = {
            "state": bot_runtime._ACTIVATION_MEDIA_CONFIRM_STATE,
            "activation_token": "tok-m1",
            "bot_client_id": bot_runtime._SESSIONS[42]["bot_client_id"],
        }
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_confirm_callback_fails_closed_when_pending_media_incomplete(self):
        self._activate_media_slug("m1", "tok-m1")
        session = bot_runtime._SESSIONS[42]
        session["state"] = bot_runtime._ACTIVATION_MEDIA_CONFIRM_STATE
        # Missing telegram_file_id — must never happen through the normal
        # flow, but Confirm must not fabricate a confirmed value from it.
        session["pending_activation_media"] = {"media_type": "image"}
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-a4m", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_confirm_validation_rejects_incomplete_or_invalid_pending_metadata(self):
        valid = {
            "telegram_file_id": "file123",
            "media_type": "image",
            "mime_type": "image/jpeg",
            "original_filename": "a.jpg",
            "file_size": 1000,
        }
        cases = {
            "empty_telegram_file_id": {**valid, "telegram_file_id": ""},
            "whitespace_telegram_file_id": {**valid, "telegram_file_id": "   "},
            "empty_media_type": {**valid, "media_type": ""},
            "unsupported_media_type": {**valid, "media_type": "not-a-real-type"},
            "missing_mime_type": {k: v for k, v in valid.items() if k != "mime_type"},
            "empty_mime_type": {**valid, "mime_type": ""},
            "mime_media_type_mismatch": {**valid, "mime_type": "video/mp4"},
            "missing_original_filename": {k: v for k, v in valid.items() if k != "original_filename"},
            "whitespace_original_filename": {**valid, "original_filename": "   "},
            "negative_file_size": {**valid, "file_size": -1},
            "zero_file_size": {**valid, "file_size": 0},
            "oversized_file_size": {**valid, "file_size": bot_runtime._MAX_TELEGRAM_MEDIA_BYTES + 1},
            "boolean_file_size": {**valid, "file_size": True},
            "non_integer_file_size": {**valid, "file_size": 12.5},
        }
        for label, pending in cases.items():
            with self.subTest(case=label):
                slug, token = f"m-{label}", f"tok-{label}"
                self._seed_confirm_state_with_pending(pending, slug=slug, token=token)
                self.mock_send_message.reset_mock()
                self.mock_answer.reset_mock()

                self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}{token}")

                self.assertNotIn(42, bot_runtime._SESSIONS)
                self.mock_answer.assert_awaited_once_with(
                    "cbq-a4m", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
                )
                self.mock_send_message.assert_not_awaited()
                self.assertEqual(self.db.query(models.MediaAsset).count(), 0)
                self.assertEqual(self.db.query(models.SlugMedia).count(), 0)
                self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
                record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == slug).first()
                self.assertEqual(record.activation_status, "unactivated")
                self.mock_download.assert_not_awaited()
                self.mock_upload.assert_not_called()

    def test_complete_valid_pending_metadata_confirms_successfully(self):
        valid = {
            "telegram_file_id": "file123",
            "media_type": "image",
            "mime_type": "image/jpeg",
            "original_filename": "a.jpg",
            "file_size": 1000,
        }
        self._seed_confirm_state_with_pending(valid, slug="m1", token="tok-m1")
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["confirmed_activation_media"], valid)
        self.mock_answer.assert_awaited_once_with("cbq-a4m")
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_MEDIA_SAVED_TEXT)

    def test_duplicate_confirm_callback_revalidates_db_state(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self._run_a4m_callback(
            f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-1"
        )
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(
            f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-2"
        )

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-2", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_duplicate_confirm_callback_is_idempotent_and_preserves_data(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self._run_a4m_callback(
            f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-1"
        )
        confirmed = dict(bot_runtime._SESSIONS[42]["confirmed_activation_media"])
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(
            f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-2"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertEqual(session["confirmed_activation_media"], confirmed)
        self.mock_answer.assert_awaited_once_with("cbq-2")
        self.mock_send_message.assert_not_awaited()

    # -- Change Media inline callback -------------------------------------------

    def test_change_media_callback_clears_pending_metadata(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(
            f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-2"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.assertNotIn("pending_activation_media", session)
        self.mock_answer.assert_awaited_once_with("cbq-2")
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_MEDIA_RETRY_TEXT)

    def test_change_media_callback_clears_confirmed_metadata_if_present(self):
        # Not reachable through the ordinary flow (Change Media is only
        # valid_session from _ACTIVATION_MEDIA_CONFIRM_STATE, and Confirm
        # already moves past that state) — but the handler must still be
        # safe if a forged/legacy session carries both keys.
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        session = bot_runtime._SESSIONS[42]
        session["confirmed_activation_media"] = {"telegram_file_id": "stale", "media_type": "image"}

        self._run_a4m_callback(f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1")

        session = bot_runtime._SESSIONS[42]
        self.assertNotIn("confirmed_activation_media", session)
        self.assertNotIn("pending_activation_media", session)

    def test_change_media_callback_performs_zero_db_or_r2_writes(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()

        self._run_a4m_callback(f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1")

        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)
        self.assertEqual(self.db.query(models.SlugMedia).count(), 0)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "unactivated")
        self.assertEqual(self.db.query(models.BotClientSlug).count(), 0)
        self.mock_download.assert_not_awaited()
        self.mock_upload.assert_not_called()

    def test_replacement_media_replaces_pending_metadata(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo(file_id="file123")

        self._run_a4m_callback(f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1")
        self._send_photo(file_id="file456", file_size=500)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_CONFIRM_STATE)
        self.assertEqual(session["pending_activation_media"]["telegram_file_id"], "file456")
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)

    def test_duplicate_change_callback_revalidates_db_state(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self._run_a4m_callback(
            f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-1"
        )
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        record.activation_status = "activated"
        self.db.commit()
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(
            f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-2"
        )

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_answer.assert_awaited_once_with(
            "cbq-2", text=bot_runtime._ACTIVATION_CALLBACK_INVALID_TEXT
        )

    def test_duplicate_change_callback_is_idempotent(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self._run_a4m_callback(
            f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-1"
        )
        self.mock_send_message.reset_mock()
        self.mock_answer.reset_mock()

        self._run_a4m_callback(
            f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1", callback_query_id="cbq-2"
        )

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.mock_answer.assert_awaited_once_with("cbq-2")
        self.mock_send_message.assert_not_awaited()

    # -- unrelated input during confirmation ----------------------------------

    def test_unrelated_text_during_confirmation_stays_in_state(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self.mock_send_message.reset_mock()

        self._run_message(42, "hello, what's next?")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_CONFIRM_STATE)
        self.mock_send_message.assert_awaited_once_with(
            42, bot_runtime._ACTIVATION_MEDIA_CONFIRM_REMINDER_TEXT
        )

    def test_unrelated_media_during_confirmation_does_not_replace_pending(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo(file_id="file123")
        pending = dict(bot_runtime._SESSIONS[42]["pending_activation_media"])
        self.mock_send_message.reset_mock()

        self._run_message(42, message={"photo": [{"file_id": "sneaky", "file_size": 500}]})

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_CONFIRM_STATE)
        self.assertEqual(session["pending_activation_media"], pending)

    # -- fail-closed cases ----------------------------------------------------

    def test_archived_slug_fails_closed_in_media_input_state(self):
        self._activate_media_slug("m1", "tok-m1")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.is_archived = True
        self.db.commit()

        self._send_photo()

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_already_activated_record_fails_closed_in_media_input_state(self):
        self._activate_media_slug("m1", "tok-m1")
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        record.activation_status = "activated"
        self.db.commit()

        self._send_photo()

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_wrong_type_slug_fails_closed_in_media_input_state(self):
        self._activate_media_slug("m1", "tok-m1")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.content_type = "url"
        self.db.commit()

        self._send_photo()

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_archived_slug_fails_closed_in_confirmation_state(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.is_archived = True
        self.db.commit()
        self.mock_send_message.reset_mock()

        self._run_message(42, "hello")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    def test_activated_record_invalidation_clears_session_safely(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        record.activation_status = "activated"
        self.db.commit()
        self.mock_send_message.reset_mock()

        self._run_message(42, "hello")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)
        # No storage of any kind exists to leak or orphan.
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)

    def test_type_changed_invalidation_clears_session_safely(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "m1").first()
        link.content_type = "url"
        self.db.commit()
        self.mock_send_message.reset_mock()

        self._run_message(42, "hello")

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)

    def test_invalid_session_missing_token_fails_closed(self):
        bot_runtime._SESSIONS[42] = {"state": bot_runtime._ACTIVATION_MEDIA_INPUT_STATE, "bot_client_id": None}

        self._send_photo()

        self.assertNotIn(42, bot_runtime._SESSIONS)
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_INVALID_LINK_TEXT)

    # -- abandonment: /start, restart — no storage garbage possible ----------

    def test_start_abandoning_pending_media_leaves_zero_media_asset_rows(self):
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self.assertIn("pending_activation_media", bot_runtime._SESSIONS[42])

        self._run_message(42, "/start")

        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})
        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)

    def test_process_restart_abandoning_pending_media_leaves_zero_media_asset_rows(self):
        # A "process restart" is simulated by wiping the in-memory
        # _SESSIONS dict directly, exactly as a real uvicorn restart would
        # (no persistence layer backs _SESSIONS) — since A4M never wrote
        # anything to the DB, there is nothing left behind to clean up.
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self.assertIn("pending_activation_media", bot_runtime._SESSIONS[42])

        bot_runtime._SESSIONS.clear()

        self.assertEqual(self.db.query(models.MediaAsset).count(), 0)

    # -- post-confirmation: Phase A5 finalizes ---------------------------------

    def test_message_after_direct_confirm_call_does_not_finalize(self):
        # _run_a4m_callback calls the handler directly, bypassing the
        # webhook route's orchestration hook — so unlike a real webhook
        # delivery, no finalize call happens yet, and the session is left
        # sitting in _ACTIVATION_SETUP_STATE with confirmed_activation_media,
        # exactly like a failed/interrupted attempt would be. A4M has no
        # typed-confirm fallback (button-only, by original design) — a
        # plain message here must NOT retry finalization (no re-download/
        # re-upload from unrelated chat text); it only gets a reminder to
        # re-tap Confirm.
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)
        self.assertIn("confirmed_activation_media", session)
        self.mock_send_message.reset_mock()

        self._run_message(42, "hi there")

        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "unactivated")
        self.mock_download.assert_not_awaited()
        self.mock_upload.assert_not_called()
        self.mock_send_message.assert_awaited_once_with(42, bot_runtime._ACTIVATION_FINALIZE_RETRY_MEDIA_TEXT)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_SETUP_STATE)

    def test_retapping_confirm_after_direct_call_finalizes(self):
        # The only retry surface for a media session is re-tapping Confirm
        # (existing UX) — the callback dispatch re-invokes
        # _finalize_activation_confirmation via the webhook route's
        # orchestration hook (simulated directly here by calling both in
        # sequence, matching what the route does).
        self._activate_media_slug("m1", "tok-m1")
        self._send_photo()
        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")

        self._run_a4m_callback(f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")
        asyncio.run(bot_runtime._finalize_activation_confirmation(42, self.db))

        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "activated")
        self.assertIsNotNone(record.owner_client_id)
        self.assertEqual(
            self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "m1").count(), 1
        )
        # Live-test defect fix: activation never keeps the chat
        # automatically authenticated — a fresh access-code login is
        # required to manage anything.
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})


class A4MWebhookCallbackDispatchTests(unittest.TestCase):
    """Integration tests through the actual webhook route: prove the new
    a4mconfirm_/a4mchange_ callback_data prefixes dispatch to
    bot_runtime._handle_a4m_confirmation_callback without disturbing the
    existing "activate_"/A4U callback dispatch."""

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
        self._download_patcher = patch.object(bot_runtime, "_download_telegram_file", new_callable=AsyncMock)
        self.mock_download = self._download_patcher.start()
        self._upload_patcher = patch.object(bot_runtime, "_upload_bytes_to_r2")
        self.mock_upload = self._upload_patcher.start()

    def tearDown(self):
        self._send_message_patcher.stop()
        self._answer_patcher.stop()
        self._download_patcher.stop()
        self._upload_patcher.stop()
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
                "data": "activate_tok-m1",
                "message": {"chat": {"id": chat_id}},
                "from": {"id": telegram_id, "username": "shopper"},
            },
        }

    def _a4m_callback_body(self, update_id, callback_query_id, data, chat_id=42):
        return {
            "update_id": update_id,
            "callback_query": {
                "id": callback_query_id,
                "data": data,
                "message": {"chat": {"id": chat_id}},
            },
        }

    def _photo_message_body(self, update_id, chat_id=42):
        return {
            "update_id": update_id,
            "message": {
                "chat": {"id": chat_id},
                "photo": [{"file_id": "file123", "file_size": 1000}],
                "from": {"id": 900, "username": "shopper"},
            },
        }

    def _seed_media_slug(self):
        link = models.RedirectLink(slug="m1", destination_url="https://example.com", content_type="media")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="m1", activation_token="tok-m1"))
        self.db.commit()

    def _drive_to_confirmation_state(self):
        self._seed_media_slug()
        self._post(self._activation_callback_body(1001, "cbq-activate"))
        self._post(self._photo_message_body(1002))

    def test_a4m_confirm_callback_finalizes_activation_immediately(self):
        # Phase A5: no second button, no extra tap — the same request that
        # dispatches the A4M Confirm callback also finalizes activation,
        # via the existing T1C download/upload path (mocked in setUp).
        self._drive_to_confirmation_state()

        response = self._post(
            self._a4m_callback_body(1003, "cbq-confirm", f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1")
        )

        self.assertEqual(response.status_code, 200)
        self.mock_download.assert_awaited_once()
        self.mock_upload.assert_called_once()
        self.assertEqual(self.db.query(models.MediaAsset).count(), 1)
        active_media = (
            self.db.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == "m1", models.SlugMedia.is_active == True)
            .all()
        )
        self.assertEqual(len(active_media), 1)
        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "activated")
        self.assertIsNotNone(record.owner_client_id)
        self.assertEqual(
            self.db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == "m1").count(), 1
        )
        # Live-test defect fix: activation never keeps the chat
        # automatically authenticated — a fresh access-code login is
        # required to manage anything.
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})

    def test_duplicate_confirm_callback_does_not_clear_authenticated_session(self):
        # A genuinely repeated tap (distinct update_id) after activation
        # already succeeded must not clear the winner's session (the
        # normal awaiting_code state activation always resets to) — the
        # session-race guard (_pop_stale_session) in A4M's own (untouched)
        # callback handler must not clobber it.
        self._drive_to_confirmation_state()

        self._post(self._a4m_callback_body(
            2001, "cbq-confirm-a", f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1"
        ))
        self._post(self._a4m_callback_body(
            2002, "cbq-confirm-b", f"{bot_runtime._A4M_CONFIRM_PAYLOAD_PREFIX}tok-m1"
        ))

        record = self.db.query(models.ActivationRecord).filter(models.ActivationRecord.slug == "m1").first()
        self.assertEqual(record.activation_status, "activated")
        self.assertEqual(self.db.query(models.MediaAsset).count(), 1)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})

    def test_existing_activate_now_callback_dispatch_is_unaffected(self):
        self._seed_media_slug()

        response = self._post(self._activation_callback_body(4001, "cbq-activate"))

        self.assertEqual(response.status_code, 200)
        client = self.db.query(models.BotClient).filter(models.BotClient.telegram_user_id == "900").first()
        self.assertIsNotNone(client)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)

    def test_change_media_callback_dispatched_through_webhook(self):
        self._drive_to_confirmation_state()

        response = self._post(self._a4m_callback_body(
            5001, "cbq-change", f"{bot_runtime._A4M_CHANGE_PAYLOAD_PREFIX}tok-m1"
        ))

        self.assertEqual(response.status_code, 200)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_MEDIA_INPUT_STATE)
        self.assertNotIn("confirmed_activation_media", session)


if __name__ == "__main__":
    unittest.main()
