"""Regression tests for the Phase A5 live-test defect fixes in bot_runtime.py.

Covers:
  1. A5 finalization success ends the chat in "awaiting_code", not
     "awaiting_slug_selection" — activation never keeps the customer
     automatically authenticated; managing anything still requires
     entering the access code.
  2. Activation/authenticated-management session keys are fully cleared on
     success (the session becomes exactly {"state": "awaiting_code"}).
  3. A later arbitrary message after activation is handled by the normal
     access-code login flow, never mistaken for numbered slug-selection
     input.
  4. A valid access code for a BotClient with exactly one active assigned
     slug auto-selects it and shows its management menu directly — no
     numbered "reply with a number between 1 and 1" list.
  5. A valid access code for a BotClient with multiple active assigned
     slugs still shows the numbered selection list as before.
  6. The "Please reply with a number between X and Y" message appears only
     in a genuine multi-slug awaiting_slug_selection state with an invalid
     reply — never elsewhere.
  7. Selecting a url slug from the numbered list goes straight to the
     current-destination/new-URL prompt in one message (no extra
     intermediate "menu" step) — unchanged existing behaviour.
  8. The url-management update-confirmation prompt now offers inline
     Confirm/Change-or-Cancel buttons as the primary UX (typed YES/NO
     remains a compatibility fallback, unchanged and separately tested in
     test_bot_runtime.py).
  9. Tapping Confirm persists the new destination URL exactly once.
  10. Tapping Change or Cancel performs no write and returns to slug
      selection.
  11. A duplicate Confirm tap (session already moved on) is idempotent —
      no second write.
  12. Stale/malformed/foreign-chat/wrong-state callbacks fail closed with
      zero DB mutation.

Uses an isolated in-memory SQLite database — never touches the real
shadz.db. No network calls: bot_runtime._send_message and
_answer_callback_query are patched with AsyncMock everywhere.
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


class DirectTestsBase(unittest.TestCase):
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

    def _make_client(self, access_code="ABC123", is_active=True):
        client = models.BotClient(
            client_name="Test Client", access_code=access_code, is_active=is_active,
        )
        self.db.add(client)
        self.db.commit()
        return client

    def _make_link(self, slug, content_type="url", destination_url="https://old.example.com", is_archived=False):
        link = models.RedirectLink(
            slug=slug, destination_url=destination_url, content_type=content_type, is_archived=is_archived,
        )
        self.db.add(link)
        self.db.commit()
        return link

    def _assign(self, client, slug):
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug=slug))
        self.db.commit()

    def _run_message(self, chat_id, text, message=None):
        message = message if message is not None else {"text": text}
        asyncio.run(bot_runtime._handle_message(chat_id, text, {"id": 999}, self.db, message))

    def _enter_confirmation_state(self, chat_id=42, slug="u1", new_url="https://new.example.com", access_code="ABC123"):
        client = self._make_client(access_code=access_code)
        self._make_link(slug, "url", destination_url="https://old.example.com")
        self._assign(client, slug)
        bot_runtime._SESSIONS[chat_id] = {
            "state": "awaiting_new_url",
            "bot_client_id": client.id,
            "slugs": [{"slug": slug, "content_type": "url", "notes": None}],
            "selected_slug": slug,
        }
        self._run_message(chat_id, new_url)
        return client


# ---------------------------------------------------------------------------
# 1-3: post-activation session state
# ---------------------------------------------------------------------------

class PostActivationSessionStateTests(DirectTestsBase):
    def _finalize_url_activation(self, chat_id=42):
        link = self._make_link("u1", "url")
        record = models.ActivationRecord(slug="u1", activation_token="tok-u1")
        self.db.add(record)
        self.db.commit()
        client = self._make_client()
        bot_runtime._SESSIONS[chat_id] = {
            "state": bot_runtime._ACTIVATION_SETUP_STATE,
            "activation_token": "tok-u1",
            "bot_client_id": client.id,
            "content_type": "url",
            "confirmed_destination_url": "https://merchant.example.com/product",
        }
        asyncio.run(bot_runtime._finalize_activation_confirmation(chat_id, self.db))
        return client, record

    def test_finalization_ends_in_awaiting_code_not_slug_selection(self):
        self._finalize_url_activation()
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_code")
        self.assertNotEqual(session["state"], "awaiting_slug_selection")

    def test_finalization_clears_all_activation_and_management_keys(self):
        self._finalize_url_activation()
        session = bot_runtime._SESSIONS[42]
        # Exactly the plain login-entry shape — nothing else survives.
        self.assertEqual(session, {"state": "awaiting_code"})
        for key in ("activation_token", "bot_client_id", "content_type",
                    "confirmed_destination_url", "slugs", "selected_slug"):
            self.assertNotIn(key, session)

    def test_later_arbitrary_message_is_treated_as_access_code_not_slug_input(self):
        client, _ = self._finalize_url_activation()
        self.mock_send_message.reset_mock()

        self._run_message(42, "Hello")

        # Must go through the access-code branch (rejects "Hello" as an
        # invalid code) — never the numbered slug-selection branch.
        self.mock_send_message.assert_awaited_once_with(
            42, "Invalid or inactive access code. Please try again."
        )
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("reply with a number", call.args[1])
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_code")

    def test_valid_access_code_works_normally_after_activation(self):
        # A5 finalization itself already creates the BotClientSlug
        # assignment (verified separately in test_activation_engine_phase_a5.py) —
        # here we only need it to already exist so login can find it.
        client, _ = self._finalize_url_activation()
        self.mock_send_message.reset_mock()

        self._run_message(42, client.access_code)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_new_url")


# ---------------------------------------------------------------------------
# 4-7: login / slug-selection UX
# ---------------------------------------------------------------------------

class LoginSlugSelectionTests(DirectTestsBase):
    def test_single_slug_auto_selects_into_management_menu(self):
        client = self._make_client()
        self._make_link("u1", "url", destination_url="https://example.com")
        self._assign(client, "u1")

        self._run_message(42, client.access_code)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_new_url")
        self.assertEqual(session["selected_slug"], "u1")
        # No numbered list was ever sent.
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("Your assigned slugs", call.args[1])
            self.assertNotIn("reply with a number", call.args[1])

    def test_single_slug_management_menu_shows_current_destination(self):
        client = self._make_client()
        self._make_link("u1", "url", destination_url="https://example.com")
        self._assign(client, "u1")

        self._run_message(42, client.access_code)

        self.mock_send_message.assert_any_await(
            42,
            "Current destination for 'u1':\nhttps://example.com\n\n"
            "Reply with the new destination URL — a domain such as example.com "
            "or a full http:// / https:// URL — or /cancel.",
        )

    def test_multiple_slugs_show_numbered_selection_list(self):
        client = self._make_client()
        self._make_link("u1", "url")
        self._make_link("u2", "url")
        self._assign(client, "u1")
        self._assign(client, "u2")

        self._run_message(42, client.access_code)

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_slug_selection")
        self.mock_send_message.assert_any_await(
            42, bot_runtime._format_slug_menu(session["slugs"])
        )

    def test_numeric_range_error_only_in_genuine_multi_slug_state(self):
        client = self._make_client()
        self._make_link("u1", "url")
        self._make_link("u2", "url")
        self._assign(client, "u1")
        self._assign(client, "u2")
        self._run_message(42, client.access_code)
        self.mock_send_message.reset_mock()

        self._run_message(42, "banana")

        self.mock_send_message.assert_awaited_once_with(
            42, "Please reply with a number between 1 and 2."
        )

    def test_numeric_range_error_never_appears_for_single_slug_state(self):
        client = self._make_client()
        self._make_link("u1", "url")
        self._assign(client, "u1")

        self._run_message(42, client.access_code)

        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("reply with a number between", call.args[1])

    def test_numeric_range_error_never_appears_outside_slug_selection(self):
        # awaiting_code, awaiting_new_url, awaiting_confirmation, etc. must
        # never emit this message regardless of what the user types.
        bot_runtime._SESSIONS[42] = {"state": "awaiting_code"}
        self._run_message(42, "banana")
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("reply with a number between", call.args[1])

    def test_selecting_url_slug_from_list_goes_straight_to_destination_prompt(self):
        client = self._make_client()
        self._make_link("u1", "url", destination_url="https://example.com")
        self._make_link("u2", "url", destination_url="https://other.example.com")
        self._assign(client, "u1")
        self._assign(client, "u2")
        self._run_message(42, client.access_code)
        self.mock_send_message.reset_mock()

        self._run_message(42, "1")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_new_url")
        # One single response carries both the current destination and the
        # prompt for a new one — no separate intermediate menu step.
        self.mock_send_message.assert_awaited_once_with(
            42,
            "Current destination for 'u1':\nhttps://example.com\n\n"
            "Reply with the new destination URL — a domain such as example.com "
            "or a full http:// / https:// URL — or /cancel.",
        )

    def test_typed_cancel_single_slug_returns_to_awaiting_code(self):
        client = self._make_client()
        self._make_link("u1", "url", destination_url="https://example.com")
        self._assign(client, "u1")
        self._run_message(42, client.access_code)  # auto-selects into awaiting_new_url
        self.mock_send_message.reset_mock()

        self._run_message(42, "/cancel")

        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})
        self.mock_send_message.assert_any_await(
            42, "Welcome to SHADZ. Please enter your access code."
        )

    def test_typed_cancel_multi_slug_returns_to_numbered_list_and_rerenders_it(self):
        client = self._make_client()
        self._make_link("u1", "url")
        self._make_link("u2", "url")
        self._assign(client, "u1")
        self._assign(client, "u2")
        self._run_message(42, client.access_code)  # numbered list
        self._run_message(42, "1")  # select u1 -> awaiting_new_url
        self.mock_send_message.reset_mock()

        self._run_message(42, "/cancel")

        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_slug_selection")
        self.mock_send_message.assert_any_await(42, bot_runtime._format_slug_menu(session["slugs"]))

    def test_no_hidden_one_item_slug_selection_state_is_reachable(self):
        # However a single-slug client's flow proceeds (login or /cancel),
        # the session must never sit in awaiting_slug_selection with a
        # 1-item list.
        client = self._make_client()
        self._make_link("u1", "url")
        self._assign(client, "u1")

        self._run_message(42, client.access_code)
        self.assertNotEqual(bot_runtime._SESSIONS[42]["state"], "awaiting_slug_selection")

        self._run_message(42, "/cancel")
        self.assertNotEqual(bot_runtime._SESSIONS[42]["state"], "awaiting_slug_selection")

    def test_arbitrary_text_never_auto_selects_a_hidden_single_item_list(self):
        # Regression for the removed auto-select safeguard: even if a
        # session somehow still carried a 1-item awaiting_slug_selection
        # shape, arbitrary text must be treated as an ordinary (invalid)
        # numbered selection, never an implicit pick.
        client = self._make_client()
        self._make_link("u1", "url")
        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_slug_selection",
            "bot_client_id": client.id,
            "slugs": [{"slug": "u1", "content_type": "url", "notes": None}],
        }

        self._run_message(42, "hello")

        session = bot_runtime._SESSIONS[42]
        self.assertNotEqual(session.get("state"), "awaiting_new_url")
        self.mock_send_message.assert_awaited_once_with(
            42, "Please reply with a number between 1 and 1."
        )


# ---------------------------------------------------------------------------
# 8-12: url-management confirmation inline buttons
# ---------------------------------------------------------------------------

class UrlManagementConfirmationButtonTests(DirectTestsBase):
    def _confirm_callback(self, chat_id=42, callback_query_id="cbq-1"):
        cq = {
            "id": callback_query_id,
            "data": bot_runtime._URL_MANAGEMENT_CONFIRM_CALLBACK,
            "message": {"chat": {"id": chat_id}},
        }
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))

    def _change_callback(self, chat_id=42, callback_query_id="cbq-1"):
        cq = {
            "id": callback_query_id,
            "data": bot_runtime._URL_MANAGEMENT_CHANGE_CALLBACK,
            "message": {"chat": {"id": chat_id}},
        }
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))

    def _cancel_callback(self, chat_id=42, callback_query_id="cbq-1"):
        cq = {
            "id": callback_query_id,
            "data": bot_runtime._URL_MANAGEMENT_CANCEL_CALLBACK,
            "message": {"chat": {"id": chat_id}},
        }
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))

    def test_confirmation_prompt_includes_inline_buttons(self):
        self._enter_confirmation_state()
        markup = bot_runtime._url_management_confirmation_markup()
        found = [
            call for call in self.mock_send_message.await_args_list
            if call.kwargs.get("reply_markup") == markup
        ]
        self.assertTrue(found)

    def test_confirm_button_persists_url_once(self):
        self._enter_confirmation_state(new_url="https://new.example.com")

        self._confirm_callback()

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")
        self.mock_answer.assert_awaited_once_with("cbq-1")

    def test_change_button_returns_to_url_input_and_performs_no_write(self):
        self._enter_confirmation_state(new_url="https://new.example.com")

        self._change_callback()

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_new_url")
        self.assertEqual(session["selected_slug"], "u1")

    def test_cancel_button_exits_correctly_for_single_slug_account(self):
        self._enter_confirmation_state(new_url="https://new.example.com")

        self._cancel_callback()

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})

    def test_cancel_button_exits_correctly_for_multi_slug_account(self):
        client = self._make_client()
        self._make_link("u1", "url", destination_url="https://old.example.com")
        self._make_link("u2", "url", destination_url="https://elsewhere.example.com")
        self._assign(client, "u1")
        self._assign(client, "u2")
        slugs = [
            {"slug": "u1", "content_type": "url", "notes": None},
            {"slug": "u2", "content_type": "url", "notes": None},
        ]
        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_new_url",
            "bot_client_id": client.id,
            "slugs": slugs,
            "selected_slug": "u1",
        }
        self._run_message(42, "https://new.example.com")
        self.mock_send_message.reset_mock()

        self._cancel_callback()

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_slug_selection")
        self.mock_send_message.assert_any_await(42, bot_runtime._format_slug_menu(slugs))

    def test_sequential_duplicate_confirm_writes_once_and_sends_success_once(self):
        self._enter_confirmation_state(new_url="https://new.example.com")

        self._confirm_callback(callback_query_id="cbq-1")
        self.mock_send_message.reset_mock()
        self._confirm_callback(callback_query_id="cbq-2")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")
        # No second "Done." completion message — the duplicate tap found
        # the session already moved on and failed closed silently (aside
        # from answering the callback).
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("Done.", call.args[1])

    def test_concurrent_duplicate_confirm_writes_once_and_sends_success_once(self):
        # Simulates a genuinely concurrent second Confirm delivery
        # interleaving during the first request's only await point
        # (_answer_callback_query) — asyncio only switches tasks at an
        # await, so this is where a real second request would interleave.
        # The claim (mutating _SESSIONS[chat_id]) happens BEFORE that
        # await, so the nested call must find the session already claimed.
        self._enter_confirmation_state(new_url="https://new.example.com")
        call_count = {"n": 0}

        async def fake_answer(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                cq2 = {
                    "id": "cbq-2",
                    "data": bot_runtime._URL_MANAGEMENT_CONFIRM_CALLBACK,
                    "message": {"chat": {"id": 42}},
                }
                await bot_runtime._handle_url_management_confirmation_callback(cq2, self.db)

        self.mock_answer.side_effect = fake_answer
        self.mock_send_message.reset_mock()

        self._confirm_callback(callback_query_id="cbq-1")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")
        done_messages = [
            call for call in self.mock_send_message.await_args_list
            if call.args[1].startswith("Done.")
        ]
        self.assertEqual(len(done_messages), 1)

    def test_concurrent_confirm_vs_change_allows_only_one_action(self):
        # A Confirm and a Change/Cancel arriving near-simultaneously must
        # not both act — whichever claims the session first wins; the
        # other finds it already claimed and does nothing.
        self._enter_confirmation_state(new_url="https://new.example.com")
        call_count = {"n": 0}

        async def fake_answer(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                cq2 = {
                    "id": "cbq-2",
                    "data": bot_runtime._URL_MANAGEMENT_CHANGE_CALLBACK,
                    "message": {"chat": {"id": 42}},
                }
                await bot_runtime._handle_url_management_confirmation_callback(cq2, self.db)

        self.mock_answer.side_effect = fake_answer

        self._confirm_callback(callback_query_id="cbq-1")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")
        session = bot_runtime._SESSIONS[42]
        # Confirm's own completion state won — Change's competing write
        # never applied.
        self.assertNotEqual(session.get("state"), "awaiting_new_url")

    def test_db_failure_rolls_back_and_leaves_safe_retryable_state(self):
        self._enter_confirmation_state(new_url="https://new.example.com")

        with patch.object(self.db, "commit", side_effect=RuntimeError("boom")):
            self._confirm_callback(callback_query_id="cbq-1")
        self.db.rollback()

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_confirmation")
        self.assertEqual(session["pending_value"], "https://new.example.com")

        # Retry succeeds cleanly once the transient condition clears.
        self._confirm_callback(callback_query_id="cbq-2")
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")

    def test_stale_wrong_state_callback_performs_no_write(self):
        client = self._make_client()
        self._make_link("u1", "url", destination_url="https://old.example.com")
        self._assign(client, "u1")
        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_slug_selection",
            "bot_client_id": client.id,
            "slugs": [{"slug": "u1", "content_type": "url", "notes": None}],
        }

        self._confirm_callback()

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        self.mock_answer.assert_awaited_once_with("cbq-1", text="This action is no longer available.")

    def test_missing_session_callback_performs_no_write(self):
        self._make_link("u1", "url", destination_url="https://old.example.com")

        self._confirm_callback()

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")

    def test_malformed_callback_data_is_ignored(self):
        cq = {"id": "cbq-x", "data": "something_unrelated", "message": {"chat": {"id": 42}}}
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))
        self.mock_answer.assert_awaited_once_with("cbq-x")
        self.mock_send_message.assert_not_awaited()

    def test_non_dict_callback_query_does_not_crash(self):
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback("not-a-dict", self.db))
        self.mock_answer.assert_not_awaited()

    def test_foreign_chat_session_mismatch_performs_no_write(self):
        # Chat 42's own session is a genuine confirmation; a callback
        # reporting a DIFFERENT chat_id (43, with no session at all) must
        # not touch chat 42's pending data.
        self._enter_confirmation_state(chat_id=42, new_url="https://new.example.com")

        cq = {"id": "cbq-1", "data": bot_runtime._URL_MANAGEMENT_CONFIRM_CALLBACK, "message": {"chat": {"id": 43}}}
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_confirmation")


# ---------------------------------------------------------------------------
# Typed YES/NO/CHANGE fallback — must produce identical results to the
# inline buttons via the shared _claim_url_management_context /
# _apply_url_management_action functions.
# ---------------------------------------------------------------------------

class TypedUrlManagementFallbackTests(DirectTestsBase):
    def _confirm_callback(self, chat_id=42, callback_query_id="cbq-1"):
        cq = {
            "id": callback_query_id,
            "data": bot_runtime._URL_MANAGEMENT_CONFIRM_CALLBACK,
            "message": {"chat": {"id": chat_id}},
        }
        asyncio.run(bot_runtime._handle_url_management_confirmation_callback(cq, self.db))

    def test_typed_yes_and_button_confirm_produce_same_result(self):
        client_a = self._make_client(access_code="CODEA")
        self._make_link("ua", "url", destination_url="https://old.example.com")
        self._assign(client_a, "ua")
        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_confirmation",
            "bot_client_id": client_a.id,
            "slugs": [{"slug": "ua", "content_type": "url", "notes": None}],
            "selected_slug": "ua",
            "pending_value": "https://new.example.com",
        }
        self._run_message(42, "YES")
        typed_link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "ua").first()
        typed_session = dict(bot_runtime._SESSIONS[42])

        client_b = self._make_client(access_code="CODEB")
        self._make_link("ub", "url", destination_url="https://old.example.com")
        self._assign(client_b, "ub")
        bot_runtime._SESSIONS[43] = {
            "state": "awaiting_confirmation",
            "bot_client_id": client_b.id,
            "slugs": [{"slug": "ub", "content_type": "url", "notes": None}],
            "selected_slug": "ub",
            "pending_value": "https://new.example.com",
        }
        self._confirm_callback(chat_id=43)
        button_link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "ub").first()
        button_session = dict(bot_runtime._SESSIONS[43])

        self.assertEqual(typed_link.destination_url, button_link.destination_url)
        self.assertEqual(typed_session, {"state": "awaiting_code"})
        self.assertEqual(button_session, {"state": "awaiting_code"})

    def test_typed_no_single_slug_returns_to_awaiting_code(self):
        self._enter_confirmation_state(new_url="https://new.example.com")
        self.mock_send_message.reset_mock()

        self._run_message(42, "NO")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        self.assertEqual(bot_runtime._SESSIONS[42], {"state": "awaiting_code"})
        self.mock_send_message.assert_any_await(
            42, "Welcome to SHADZ. Please enter your access code."
        )

    def test_typed_cancel_multi_slug_rerenders_numbered_list(self):
        client = self._make_client()
        self._make_link("u1", "url", destination_url="https://old.example.com")
        self._make_link("u2", "url")
        self._assign(client, "u1")
        self._assign(client, "u2")
        slugs = [
            {"slug": "u1", "content_type": "url", "notes": None},
            {"slug": "u2", "content_type": "url", "notes": None},
        ]
        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_confirmation",
            "bot_client_id": client.id,
            "slugs": slugs,
            "selected_slug": "u1",
            "pending_value": "https://new.example.com",
        }
        self.mock_send_message.reset_mock()

        self._run_message(42, "cancel")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_slug_selection")
        self.mock_send_message.assert_any_await(42, bot_runtime._format_slug_menu(slugs))

    def test_typed_change_returns_to_url_input_with_no_write(self):
        self._enter_confirmation_state(new_url="https://new.example.com")

        self._run_message(42, "change")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://old.example.com")
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], "awaiting_new_url")
        self.assertEqual(session["selected_slug"], "u1")

    def test_typed_duplicate_yes_is_idempotent(self):
        self._enter_confirmation_state(new_url="https://new.example.com")

        self._run_message(42, "YES")
        self.mock_send_message.reset_mock()
        self._run_message(42, "YES")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")
        for call in self.mock_send_message.await_args_list:
            self.assertNotIn("Done.", call.args[1])

    def test_typed_yes_racing_button_confirm_persists_and_reports_success_once(self):
        # Simulates a genuinely concurrent delivery: a typed "YES" message
        # and a button Confirm tap racing each other. The button path's
        # only await (_answer_callback_query) is where a real interleaving
        # would occur — the claim (no await in between) is what decides
        # which one wins.
        self._enter_confirmation_state(new_url="https://new.example.com")
        call_count = {"n": 0}

        async def fake_answer(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # await directly rather than through self._run_message
                # (which wraps in asyncio.run) — already inside a running
                # event loop here, so a nested asyncio.run would raise.
                await bot_runtime._handle_message(42, "YES", {"id": 999}, self.db, {"text": "YES"})

        self.mock_answer.side_effect = fake_answer
        self.mock_send_message.reset_mock()

        self._confirm_callback(callback_query_id="cbq-1")

        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")
        done_messages = [
            call for call in self.mock_send_message.await_args_list
            if call.args[1].startswith("Done.")
        ]
        self.assertEqual(len(done_messages), 1)

    def test_no_url_confirmation_path_calls_reset_to_slug_menu(self):
        # _reset_to_slug_menu must no longer be reachable from any
        # awaiting_confirmation code path (button or typed) — only the
        # unrelated media-upload guard still uses it.
        with patch.object(bot_runtime, "_reset_to_slug_menu") as mock_reset:
            self._enter_confirmation_state(new_url="https://new.example.com")
            self._run_message(42, "YES")
            mock_reset.assert_not_called()

        self._enter_confirmation_state(
            chat_id=43, slug="u2", new_url="https://new.example.com", access_code="XYZ999"
        )
        with patch.object(bot_runtime, "_reset_to_slug_menu") as mock_reset:
            self._confirm_callback(chat_id=43)
            mock_reset.assert_not_called()


# ---------------------------------------------------------------------------
# Webhook-route integration: prove the new callback prefix dispatches
# correctly alongside the existing activation-engine callback routing.
# ---------------------------------------------------------------------------

class UrlManagementWebhookDispatchTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool,
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

    def test_confirm_callback_dispatched_through_webhook_persists_url(self):
        client = models.BotClient(client_name="Test", access_code="AB12CD", is_active=True)
        self.db.add(client)
        link = models.RedirectLink(slug="u1", destination_url="https://old.example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.BotClientSlug(bot_client_id=client.id, slug="u1"))
        self.db.commit()
        bot_runtime._SESSIONS[42] = {
            "state": "awaiting_new_url",
            "bot_client_id": client.id,
            "slugs": [{"slug": "u1", "content_type": "url", "notes": None}],
            "selected_slug": "u1",
        }
        asyncio.run(bot_runtime._handle_message(42, "https://new.example.com", {}, self.db, {"text": "https://new.example.com"}))

        response = self._post({
            "update_id": 9001,
            "callback_query": {
                "id": "cbq-1",
                "data": bot_runtime._URL_MANAGEMENT_CONFIRM_CALLBACK,
                "message": {"chat": {"id": 42}},
            },
        })

        self.assertEqual(response.status_code, 200)
        link = self.db.query(models.RedirectLink).filter(models.RedirectLink.slug == "u1").first()
        self.assertEqual(link.destination_url, "https://new.example.com")

    def test_existing_activation_callback_dispatch_unaffected(self):
        # A callback for an unrelated "activate_" token must still route to
        # the activation-engine path, not the new url-management handler.
        link = models.RedirectLink(slug="u1", destination_url="https://example.com", content_type="url")
        self.db.add(link)
        self.db.commit()
        self.db.add(models.ActivationRecord(slug="u1", activation_token="tok-u1"))
        self.db.commit()

        response = self._post({
            "update_id": 9002,
            "callback_query": {
                "id": "cbq-2",
                "data": "activate_tok-u1",
                "message": {"chat": {"id": 42}},
                "from": {"id": 900, "username": "shopper"},
            },
        })

        self.assertEqual(response.status_code, 200)
        session = bot_runtime._SESSIONS[42]
        self.assertEqual(session["state"], bot_runtime._ACTIVATION_URL_INPUT_STATE)


if __name__ == "__main__":
    unittest.main()
