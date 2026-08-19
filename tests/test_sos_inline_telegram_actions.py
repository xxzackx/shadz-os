"""Regression tests for the urgent Safety Engine v1 live-testing fix: SOS
Telegram inline Acknowledge/Resolve buttons.

Two halves:

1. Unit tests on safety_telegram.py's new pieces (_sos_inline_keyboard,
   _format_sos's status line, send_sos_notification's reply_markup,
   edit_sos_message) with _send_telegram_message mocked -- no real network
   call, following test_safety_telegram_routing_s6_1.py's existing pattern.

2. Webhook integration tests on bot_runtime.py's new callback_data prefix
   dispatch ("sos_ack:"/"sos_resolve:"), following
   test_bot_runtime_management_flow.py's UrlManagementWebhookDispatchTests
   pattern: register_bot_webhook_routes on a bare FastAPI app (no main.py
   import), in-memory SQLite, TELEGRAM_WEBHOOK_SECRET patched,
   bot_runtime._answer_callback_query and safety_telegram.edit_sos_message
   mocked so no real network call happens.

Both halves reuse the real safety_notify.acknowledge_sos/resolve_sos (never
mocked) -- the point of this file is to prove the Telegram button path
reaches that exact same S7 lifecycle code that safety_admin.py's admin
routes already use, not a parallel implementation.
"""
import asyncio
import os
import sys
import unittest
from datetime import datetime, time, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import bot_runtime
import models
import safety_telegram
from database import Base, get_db

_ADMIN_CHAT_ID = 999999
_OTHER_CHAT_ID = 111111


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Unit tests: safety_telegram.py additions
# ---------------------------------------------------------------------------

class SOSInlineKeyboardUnitTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()
        self._chat_env = patch.dict(os.environ, {"SAFETY_TELEGRAM_CHAT_ID": str(_ADMIN_CHAT_ID)})
        self._chat_env.start()

    def tearDown(self):
        self._chat_env.stop()
        self.db.close()

    def _make_user(self):
        user = models.SafetyUser(
            display_name="Alice", timezone="UTC", daily_deadline=time(21, 0),
            early_reminder_minutes=30, nfc_token="tok-sos-inline", is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def _make_emergency(self, user, status="open"):
        emergency = models.SafetyEmergency(user_id=user.id, status=status)
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)
        return emergency

    # ── keyboard shape driven only by status ─────────────────────────────

    def test_open_status_yields_acknowledge_button(self):
        keyboard = safety_telegram._sos_inline_keyboard(7, "open")
        self.assertEqual(
            keyboard,
            {"inline_keyboard": [[{"text": "ACKNOWLEDGE", "callback_data": "sos_ack:7"}]]},
        )

    def test_acknowledged_status_yields_resolve_button(self):
        keyboard = safety_telegram._sos_inline_keyboard(7, "acknowledged")
        self.assertEqual(
            keyboard,
            {"inline_keyboard": [[{"text": "RESOLVE", "callback_data": "sos_resolve:7"}]]},
        )

    def test_resolved_status_yields_no_keyboard_for_send(self):
        # for_edit defaults False -- the initial sendMessage path, where
        # there is no prior keyboard to remove.
        self.assertIsNone(safety_telegram._sos_inline_keyboard(7, "resolved"))

    def test_unknown_status_yields_no_keyboard_for_send(self):
        self.assertIsNone(safety_telegram._sos_inline_keyboard(7, "something_else"))

    def test_resolved_status_for_edit_yields_explicit_empty_keyboard(self):
        # The blocking fix: editing an existing message must send an
        # explicit {"inline_keyboard": []}, never None/omission -- Telegram
        # does not remove an already-attached keyboard on editMessageText
        # unless reply_markup is actually present in the request.
        self.assertEqual(
            safety_telegram._sos_inline_keyboard(7, "resolved", for_edit=True),
            {"inline_keyboard": []},
        )

    def test_unknown_status_for_edit_yields_explicit_empty_keyboard(self):
        self.assertEqual(
            safety_telegram._sos_inline_keyboard(7, "something_else", for_edit=True),
            {"inline_keyboard": []},
        )

    def test_open_and_acknowledged_status_unaffected_by_for_edit_flag(self):
        self.assertEqual(
            safety_telegram._sos_inline_keyboard(7, "open", for_edit=True),
            safety_telegram._sos_inline_keyboard(7, "open", for_edit=False),
        )
        self.assertEqual(
            safety_telegram._sos_inline_keyboard(7, "acknowledged", for_edit=True),
            safety_telegram._sos_inline_keyboard(7, "acknowledged", for_edit=False),
        )

    # ── _format_sos status line ───────────────────────────────────────────

    def test_format_sos_includes_status_line(self):
        user = self._make_user()
        emergency = self._make_emergency(user, status="open")
        message = safety_telegram._format_sos(user, emergency)
        self.assertIn("Status: OPEN", message)

        emergency.status = "acknowledged"
        message = safety_telegram._format_sos(user, emergency)
        self.assertIn("Status: ACKNOWLEDGED", message)

        emergency.status = "resolved"
        message = safety_telegram._format_sos(user, emergency)
        self.assertIn("Status: RESOLVED", message)

    # ── send_sos_notification attaches the right keyboard ────────────────

    def _patch_send(self, return_value=True):
        return patch.object(
            safety_telegram, "_send_telegram_message", new_callable=AsyncMock,
            return_value=return_value,
        )

    def test_open_sos_notification_includes_acknowledge_button(self):
        user = self._make_user()
        emergency = self._make_emergency(user, status="open")
        with self._patch_send() as mock_send:
            sent = _run(safety_telegram.send_sos_notification(user, emergency))
        self.assertTrue(sent)
        mock_send.assert_awaited_once()
        args, kwargs = mock_send.call_args
        self.assertEqual(args[0], _ADMIN_CHAT_ID)
        self.assertEqual(
            kwargs["reply_markup"],
            {"inline_keyboard": [[{"text": "ACKNOWLEDGE", "callback_data": f"sos_ack:{emergency.id}"}]]},
        )

    def test_acknowledged_sos_notification_includes_resolve_button(self):
        # Escalation retries re-send while status is "acknowledged" too
        # (see _SOS_ESCALATION_STATUSES) -- each such retry must carry a
        # working Resolve button, not a stale Acknowledge one.
        user = self._make_user()
        emergency = self._make_emergency(user, status="acknowledged")
        with self._patch_send() as mock_send:
            _run(safety_telegram.send_sos_notification(user, emergency))
        _, kwargs = mock_send.call_args
        self.assertEqual(
            kwargs["reply_markup"],
            {"inline_keyboard": [[{"text": "RESOLVE", "callback_data": f"sos_resolve:{emergency.id}"}]]},
        )

    def test_resolved_sos_notification_has_no_keyboard(self):
        # reply_markup is None for a resolved SOS, so _send omits the kwarg
        # entirely (same "no keyboard" outcome as passing reply_markup=None
        # -- Telegram's sendMessage just never receives the key either way).
        user = self._make_user()
        emergency = self._make_emergency(user, status="resolved")
        with self._patch_send() as mock_send:
            _run(safety_telegram.send_sos_notification(user, emergency))
        _, kwargs = mock_send.call_args
        self.assertIsNone(kwargs.get("reply_markup"))

    def test_non_sos_sends_do_not_pass_reply_markup_kwarg(self):
        # Regression guard: early_reminder/missed_checkin/late_checkin must
        # keep their exact pre-existing call shape (no reply_markup kwarg
        # at all) -- only SOS attaches a keyboard.
        user = self._make_user()
        user.telegram_chat_id = 555555
        self.db.commit()
        with self._patch_send() as mock_send:
            sent = _run(safety_telegram.send_early_reminder(user))
        self.assertTrue(sent)
        self.assertNotIn("reply_markup", mock_send.call_args.kwargs)


class EditSOSMessageUnitTests(unittest.TestCase):
    """edit_sos_message's own honest-success-signal contract, mirroring
    _send_telegram_message's existing test coverage style."""

    def test_edit_returns_true_only_on_confirmed_ok(self):
        mock_response = unittest.mock.Mock()
        mock_response.raise_for_status = unittest.mock.Mock()
        mock_response.json = unittest.mock.Mock(return_value={"ok": True, "result": {}})

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "test-token"}):
            with patch("httpx.AsyncClient", return_value=mock_client):
                result = _run(safety_telegram.edit_sos_message(_ADMIN_CHAT_ID, 42, "text", None))
        self.assertTrue(result)

    def test_edit_returns_false_when_ok_is_not_true(self):
        mock_response = unittest.mock.Mock()
        mock_response.raise_for_status = unittest.mock.Mock()
        mock_response.json = unittest.mock.Mock(return_value={"ok": False})

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.post = AsyncMock(return_value=mock_response)

        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": "test-token"}):
            with patch("httpx.AsyncClient", return_value=mock_client):
                result = _run(safety_telegram.edit_sos_message(_ADMIN_CHAT_ID, 42, "text", None))
        self.assertFalse(result)

    def test_edit_returns_false_without_token(self):
        with patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": ""}):
            result = _run(safety_telegram.edit_sos_message(_ADMIN_CHAT_ID, 42, "text", None))
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# Webhook integration tests: bot_runtime.py's callback_data dispatch
# ---------------------------------------------------------------------------

class SOSInlineWebhookDispatchTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()
        self.SessionLocal = SessionLocal

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

        self._env_patcher = patch.dict(os.environ, {
            "TELEGRAM_WEBHOOK_SECRET": "test-secret",
            "SAFETY_TELEGRAM_CHAT_ID": str(_ADMIN_CHAT_ID),
        })
        self._env_patcher.start()

        self._answer_patcher = patch.object(bot_runtime, "_answer_callback_query", new_callable=AsyncMock)
        self.mock_answer = self._answer_patcher.start()
        self._edit_patcher = patch.object(safety_telegram, "edit_sos_message", new_callable=AsyncMock, return_value=True)
        self.mock_edit = self._edit_patcher.start()
        # BotClient/activation dispatch must remain untouched -- mocked
        # only so an accidental fall-through never makes a real network call.
        self._send_message_patcher = patch.object(bot_runtime, "_send_message", new_callable=AsyncMock)
        self.mock_send_message = self._send_message_patcher.start()

    def tearDown(self):
        self._answer_patcher.stop()
        self._edit_patcher.stop()
        self._send_message_patcher.stop()
        self._env_patcher.stop()
        self.db.close()
        bot_runtime._SEEN_UPDATE_IDS.clear()
        bot_runtime._SESSIONS.clear()

    def _post(self, body):
        response = self.client.post(
            "/bot/telegram/webhook", json=body,
            headers={"X-Telegram-Bot-Api-Secret-Token": "test-secret"},
        )
        # The webhook request handles its own DB session (via the
        # dependency override), separate from self.db -- expire self.db's
        # identity map so a subsequent self.db.query(...) re-reads the
        # committed row instead of returning a stale cached instance.
        self.db.expire_all()
        return response

    def _make_user_and_emergency(self, status="open"):
        user = models.SafetyUser(
            display_name="Alice", timezone="UTC", daily_deadline=time(21, 0),
            early_reminder_minutes=30, nfc_token="tok-webhook-sos", is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        emergency = models.SafetyEmergency(user_id=user.id, status=status)
        if status == "acknowledged":
            emergency.acknowledged_at = datetime.now(timezone.utc)
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)
        return user, emergency

    def _sos_callback_body(self, update_id, data, chat_id=_ADMIN_CHAT_ID, message_id=555):
        return {
            "update_id": update_id,
            "callback_query": {
                "id": f"cbq-{update_id}",
                "data": data,
                "message": {"chat": {"id": chat_id}, "message_id": message_id},
                "from": {"id": chat_id},
            },
        }

    # ── valid admin acknowledge ──────────────────────────────────────────

    def test_valid_admin_callback_acknowledges_using_existing_lifecycle(self):
        user, emergency = self._make_user_and_emergency(status="open")
        response = self._post(self._sos_callback_body(1001, f"sos_ack:{emergency.id}"))
        self.assertEqual(response.status_code, 200)

        reloaded = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first()
        self.assertEqual(reloaded.status, "acknowledged")
        self.assertIsNotNone(reloaded.acknowledged_at)
        self.mock_answer.assert_awaited()

    def test_acknowledged_message_edit_exposes_resolve_button(self):
        user, emergency = self._make_user_and_emergency(status="open")
        self._post(self._sos_callback_body(1002, f"sos_ack:{emergency.id}"))

        self.mock_edit.assert_awaited_once()
        args, kwargs = self.mock_edit.call_args
        # edit_sos_message(chat_id, message_id, text, reply_markup)
        self.assertEqual(args[0], _ADMIN_CHAT_ID)
        self.assertEqual(args[1], 555)
        self.assertIn("ACKNOWLEDGED", args[2])
        self.assertEqual(
            args[3],
            {"inline_keyboard": [[{"text": "RESOLVE", "callback_data": f"sos_resolve:{emergency.id}"}]]},
        )

    def test_repeated_acknowledge_callback_is_idempotent(self):
        user, emergency = self._make_user_and_emergency(status="open")
        self._post(self._sos_callback_body(1003, f"sos_ack:{emergency.id}"))
        first_ack_at = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first().acknowledged_at

        response = self._post(self._sos_callback_body(1004, f"sos_ack:{emergency.id}"))
        self.assertEqual(response.status_code, 200)
        reloaded = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first()
        self.assertEqual(reloaded.status, "acknowledged")
        self.assertEqual(reloaded.acknowledged_at, first_ack_at)

    # ── valid admin resolve ──────────────────────────────────────────────

    def test_valid_resolve_callback_resolves_and_removes_keyboard(self):
        user, emergency = self._make_user_and_emergency(status="acknowledged")
        response = self._post(self._sos_callback_body(1005, f"sos_resolve:{emergency.id}"))
        self.assertEqual(response.status_code, 200)

        reloaded = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first()
        self.assertEqual(reloaded.status, "resolved")
        self.assertIsNotNone(reloaded.resolved_at)

        self.mock_edit.assert_awaited_once()
        args, _ = self.mock_edit.call_args
        self.assertIn("RESOLVED", args[2])
        # Must be an explicit empty keyboard, not None -- Telegram does not
        # remove an existing inline keyboard on editMessageText when
        # reply_markup is merely omitted/None, only when it is present.
        self.assertEqual(args[3], {"inline_keyboard": []})

    def test_repeated_resolve_callback_is_idempotent(self):
        user, emergency = self._make_user_and_emergency(status="acknowledged")
        self._post(self._sos_callback_body(1006, f"sos_resolve:{emergency.id}"))
        first_resolved_at = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first().resolved_at

        response = self._post(self._sos_callback_body(1007, f"sos_resolve:{emergency.id}"))
        self.assertEqual(response.status_code, 200)
        reloaded = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first()
        self.assertEqual(reloaded.status, "resolved")
        self.assertEqual(reloaded.resolved_at, first_resolved_at)

    # ── locked S7 lifecycle: direct open -> resolve remains impossible ───

    def test_direct_open_to_resolve_callback_is_rejected(self):
        user, emergency = self._make_user_and_emergency(status="open")
        response = self._post(self._sos_callback_body(1008, f"sos_resolve:{emergency.id}"))
        self.assertEqual(response.status_code, 200)

        reloaded = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first()
        self.assertEqual(reloaded.status, "open")
        self.assertIsNone(reloaded.resolved_at)
        # Rejected before ever touching the Telegram message.
        self.mock_edit.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with(
            "cbq-1008", text=bot_runtime._SOS_CALLBACK_CONFLICT_TEXT
        )

    # ── fail-closed: non-admin chat ───────────────────────────────────────

    def test_callback_from_non_admin_chat_is_rejected(self):
        user, emergency = self._make_user_and_emergency(status="open")
        response = self._post(
            self._sos_callback_body(1009, f"sos_ack:{emergency.id}", chat_id=_OTHER_CHAT_ID)
        )
        self.assertEqual(response.status_code, 200)

        reloaded = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first()
        self.assertEqual(reloaded.status, "open")
        self.assertIsNone(reloaded.acknowledged_at)
        self.mock_edit.assert_not_awaited()
        self.mock_answer.assert_awaited_once_with(
            "cbq-1009", text=bot_runtime._SOS_CALLBACK_UNAUTHORIZED_TEXT
        )

    def test_callback_from_non_admin_chat_resolve_is_also_rejected(self):
        user, emergency = self._make_user_and_emergency(status="acknowledged")
        response = self._post(
            self._sos_callback_body(1010, f"sos_resolve:{emergency.id}", chat_id=_OTHER_CHAT_ID)
        )
        self.assertEqual(response.status_code, 200)
        reloaded = self.db.query(models.SafetyEmergency).filter(
            models.SafetyEmergency.id == emergency.id
        ).first()
        self.assertEqual(reloaded.status, "acknowledged")
        self.assertIsNone(reloaded.resolved_at)

    # ── stale/unknown emergency ids never crash the webhook ──────────────

    def test_unknown_emergency_id_does_not_crash_webhook(self):
        response = self._post(self._sos_callback_body(1011, "sos_ack:999999"))
        self.assertEqual(response.status_code, 200)
        self.mock_answer.assert_awaited_once_with("cbq-1011", text=bot_runtime._SOS_CALLBACK_NOT_FOUND_TEXT)
        self.mock_edit.assert_not_awaited()

    def test_malformed_emergency_id_does_not_crash_webhook(self):
        response = self._post(self._sos_callback_body(1012, "sos_ack:not-a-number"))
        self.assertEqual(response.status_code, 200)
        self.mock_answer.assert_awaited_once_with("cbq-1012", text=bot_runtime._SOS_CALLBACK_NOT_FOUND_TEXT)
        self.mock_edit.assert_not_awaited()

    # ── acknowledged SOS continues escalation, resolved stops it ─────────

    def test_acknowledged_sos_remains_escalation_eligible(self):
        import safety_notify
        user, emergency = self._make_user_and_emergency(status="open")
        self._post(self._sos_callback_body(1013, f"sos_ack:{emergency.id}"))
        due = safety_notify.collect_due_sos_notifications(self.db, datetime.now(timezone.utc))
        self.assertTrue(any(e.id == emergency.id for _, e, _ in due))

    def test_resolved_sos_stops_escalation(self):
        import safety_notify
        user, emergency = self._make_user_and_emergency(status="acknowledged")
        self._post(self._sos_callback_body(1014, f"sos_resolve:{emergency.id}"))
        due = safety_notify.collect_due_sos_notifications(self.db, datetime.now(timezone.utc))
        self.assertFalse(any(e.id == emergency.id for _, e, _ in due))

    # ── BotClient/activation dispatch unaffected ──────────────────────────

    def test_existing_activation_callback_dispatch_unaffected(self):
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db.commit()

        response = self._post({
            "update_id": 1015,
            "callback_query": {
                "id": "cbq-1015",
                "data": "activate_tok-u1",
                "message": {"chat": {"id": 42}},
                "from": {"id": 900, "username": "shopper"},
            },
        })
        self.assertEqual(response.status_code, 200)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)

    def test_botclient_message_dispatch_unaffected_by_sos_handling(self):
        # A normal BotClient text-message update must still go through
        # _handle_message exactly as before -- the SOS branch only
        # intercepts callback_query updates with the "sos_" prefixes.
        response = self._post({
            "update_id": 1016,
            "message": {
                "chat": {"id": 77},
                "text": "hello",
                "from": {"id": 77},
            },
        })
        self.assertEqual(response.status_code, 200)
        self.mock_send_message.assert_awaited()

    def test_botclient_own_callback_prefixes_still_reach_activation_handler(self):
        # An SOS-looking prefix must never shadow a BotClient/activation
        # callback whose data happens to be an unrelated string -- the
        # final else branch (_handle_activation_callback) must still be
        # reached for anything not matching a known prefix/literal.
        response = self._post({
            "update_id": 1017,
            "callback_query": {
                "id": "cbq-1017",
                "data": "some_other_unrelated_callback",
                "message": {"chat": {"id": 42}},
                "from": {"id": 900},
            },
        })
        self.assertEqual(response.status_code, 200)
        # No crash, no SOS handling invoked.
        self.mock_edit.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
