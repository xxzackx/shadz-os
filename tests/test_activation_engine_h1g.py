"""Regression tests for Hotfix H1G — authenticated Telegram session identity
revalidation.

Covers:
  1. Authenticated session + matching Telegram sender id: existing
     authenticated action (e.g. submitting a new destination URL) still
     works exactly as before.
  2. Authenticated session + a DIFFERENT Telegram sender id in the same
     chat_id: the session is cleared back to "awaiting_code" and the
     action is blocked (never reaches the authenticated handler).
  3. A mismatched identity cannot manage assigned slugs — the destination
     URL is left untouched and the customer is sent back to the
     access-code login prompt.
  4. Inactive-BotClient revalidation (existing Phase T1G behaviour) is
     unchanged by the new identity check.
  5. H1B telegram_username refresh on login still works for a valid
     authenticated identity.

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message is patched with an
AsyncMock.
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


class H1GBase(unittest.TestCase):
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

    def _make_client(self, access_code="ABC123", is_active=True, telegram_user_id="111"):
        client = models.BotClient(
            client_name="Test Client", access_code=access_code, is_active=is_active,
            telegram_user_id=telegram_user_id,
        )
        self.db.add(client)
        self.db.commit()
        return client

    def _make_link(self, slug, content_type="url", destination_url="https://old.example.com"):
        link = models.RedirectLink(
            slug=slug, destination_url=destination_url, content_type=content_type,
        )
        self.db.add(link)
        self.db.commit()
        return link

    def _assign(self, client, slug):
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug=slug))
        self.db.commit()

    def _run_message(self, chat_id, text, sender_id, message=None):
        message = message if message is not None else {"text": text}
        asyncio.run(
            bot_runtime._handle_message(chat_id, text, {"id": sender_id}, self.db, message)
        )

    def _enter_management_session(self, chat_id, client, slug):
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_new_url",
            "bot_client_id": client.id,
            "slugs": [{"slug": slug, "content_type": "url", "notes": None}],
            "selected_slug": slug,
        }

    def _enter_confirmation_session(self, chat_id, client, slug, pending_value):
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_confirmation",
            "bot_client_id": client.id,
            "slugs": [{"slug": slug, "content_type": "url", "notes": None}],
            "selected_slug": slug,
            "pending_value": pending_value,
        }

    def _confirm_callback(self, chat_id, sender_id, callback_query_id="cbq-1"):
        cq = {
            "id": callback_query_id,
            "data": bot_runtime._URL_MANAGEMENT_CONFIRM_CALLBACK,
            "message": {"chat": {"id": chat_id}},
            "from": {"id": sender_id},
        }
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))


class MatchingIdentityStillWorksTests(H1GBase):
    def test_matching_sender_id_authenticated_action_still_works(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_management_session(42, client, "u1")

        self._run_message(42, "https://new.example.com", sender_id=111)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_confirmation")
        self.assertEqual(session["pending_value"], "https://new.example.com")


class MismatchedIdentityBlockedTests(H1GBase):
    def test_different_sender_id_clears_session_and_blocks_action(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_management_session(42, client, "u1")

        self._run_message(42, "https://new.example.com", sender_id=222)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})
        self.mock_send_message.assert_awaited_once_with(
            42,
            "This session is no longer valid for your Telegram account. "
            "Please enter your access code to continue.",
        )

    def test_mismatched_identity_sent_back_to_login_flow(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_management_session(42, client, "u1")

        self._run_message(42, "https://new.example.com", sender_id=222)
        self.mock_send_message.reset_mock()

        # A later message from the mismatched sender must go through the
        # ordinary access-code login branch, not any authenticated state.
        self._run_message(42, "hello", sender_id=222)

        self.mock_send_message.assert_awaited_once_with(
            42, "Invalid or inactive access code. Please try again."
        )

    def test_mismatched_identity_cannot_manage_assigned_slugs(self):
        client = self._make_client(telegram_user_id="111")
        link = self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_management_session(42, client, "u1")

        self._run_message(42, "https://new.example.com", sender_id=222)

        refreshed = self.db.query(models.RedirectLink).filter(
            models.RedirectLink.slug == "u1"
        ).first()
        self.assertEqual(refreshed.destination_url, "https://old.example.com")

    def test_mismatch_blocks_at_awaiting_slug_selection_state_too(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._make_link("u2", destination_url="https://old2.example.com")
        self._assign(client, "u1")
        self._assign(client, "u2")
        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_slug_selection",
            "bot_client_id": client.id,
            "slugs": [
                {"slug": "u1", "content_type": "url", "notes": None},
                {"slug": "u2", "content_type": "url", "notes": None},
            ],
        }

        self._run_message(42, "1", sender_id=222)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})


class InactiveClientBehaviorUnchangedTests(H1GBase):
    def test_inactive_bot_client_still_deactivates_session_as_before(self):
        client = self._make_client(telegram_user_id="111", is_active=False)
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_management_session(42, client, "u1")

        # Same Telegram sender as the (now inactive) client's owner —
        # identity would match, but the existing active-check must still
        # fire first, unaffected by H1G.
        self._run_message(42, "https://new.example.com", sender_id=111)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})
        self.mock_send_message.assert_awaited_once_with(
            42,
            "Your access has been deactivated. Please contact the admin, "
            "or enter a new access code if you have one.",
        )


class H1BUsernameRefreshStillWorksTests(H1GBase):
    def test_username_refreshes_on_login_for_matching_identity(self):
        client = self._make_client(telegram_user_id="111")
        client.telegram_username = "old_handle"
        self.db.commit()
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")

        asyncio.run(
            bot_runtime._handle_message(
                42, client.access_code, {"id": 111, "username": "new_handle"},
                self.db, {"text": client.access_code},
            )
        )

        refreshed = self.db.query(models.BotClient).filter(
            models.BotClient.id == client.id
        ).first()
        self.assertEqual(refreshed.telegram_username, "new_handle")
        self.assertEqual(refreshed.telegram_user_id, "111")


class CallbackMatchingIdentityStillWorksTests(H1GBase):
    def test_matching_sender_id_confirm_callback_succeeds(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        self._confirm_callback(42, sender_id=111)

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")


class CallbackMismatchedIdentityBlockedTests(H1GBase):
    def test_mismatched_callback_is_blocked_reset_and_sent_login_instruction(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        with patch.object(bot_runtime, "_answer_callback_query", new_callable=AsyncMock) as mock_answer:
            self._confirm_callback(42, sender_id=222)

            # Blocked: callback answered safely (no crash, no exception raised).
            mock_answer.assert_awaited_once_with(
                "cbq-1", text=bot_runtime._URL_MANAGEMENT_UNAVAILABLE_TEXT
            )

        # Session reset to the login state.
        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})

        # No DB write — destination untouched.
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")

        # The H1G login/access-code instruction was sent exactly once.
        self.mock_send_message.assert_awaited_once_with(
            42,
            "This session is no longer valid for your Telegram account. "
            "Please enter your access code to continue.",
        )

    def test_different_sender_id_confirm_callback_is_blocked(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        self._confirm_callback(42, sender_id=222)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})

    def test_mismatched_callback_identity_does_not_change_destination(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        self._confirm_callback(42, sender_id=222)

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")

    def test_mismatched_callback_identity_answers_with_no_write_and_no_completion(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        with patch.object(bot_runtime, "_answer_callback_query", new_callable=AsyncMock) as mock_answer:
            self._confirm_callback(42, sender_id=222)
            mock_answer.assert_awaited_once_with(
                "cbq-1", text=bot_runtime._URL_MANAGEMENT_UNAVAILABLE_TEXT
            )
        # No completion/"Done." message was ever sent for the blocked action.
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("Done.", call.args[1])

    def test_missing_from_on_callback_is_treated_as_mismatch(self):
        client = self._make_client(telegram_user_id="111")
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        cq = {
            "id": "cbq-1",
            "data": bot_runtime._URL_MANAGEMENT_CONFIRM_CALLBACK,
            "message": {"chat": {"id": 42}},
        }
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})


class CallbackInactiveClientBehaviorUnchangedTests(H1GBase):
    def test_inactive_bot_client_callback_still_blocked_with_matching_identity(self):
        client = self._make_client(telegram_user_id="111", is_active=False)
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        # Same Telegram sender as the (now inactive) client's owner —
        # identity would match, but inactive still fails closed.
        self._confirm_callback(42, sender_id=111)

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session, {"state": "awaiting_code"})

    def test_inactive_bot_client_callback_never_sends_h1g_identity_message(self):
        # Regression: an inactive/missing BotClient must be treated as the
        # pre-H1G "no longer available" case, never as an H1G identity
        # mismatch — even though _resolve_authenticated_bot_client also
        # returns None for this case internally.
        client = self._make_client(telegram_user_id="111", is_active=False)
        self._make_link("u1", destination_url="https://old.example.com")
        self._assign(client, "u1")
        self._enter_confirmation_session(42, client, "u1", "https://new.example.com")

        with patch.object(bot_runtime, "_answer_callback_query", new_callable=AsyncMock) as mock_answer:
            self._confirm_callback(42, sender_id=111)

            # Existing pre-H1G callback behaviour: generic "unavailable"
            # toast, same as any other failed claim.
            mock_answer.assert_awaited_once_with(
                "cbq-1", text=bot_runtime._URL_MANAGEMENT_UNAVAILABLE_TEXT
            )

        # The H1G identity-mismatch instruction must never be sent for a
        # plain inactive/missing BotClient.
        self.mock_send_message.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
