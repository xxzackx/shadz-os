"""Regression tests for Safety Engine v1 Phase S6.1 (Telegram Recipient
Separation), covering:

  - Early reminder always routes to the target SafetyUser's own
    telegram_chat_id -- never SHADZ Admin's SAFETY_TELEGRAM_CHAT_ID, and
    never falls back to Admin (or another user) when it is missing/invalid.
  - Missed-checkin, late-checkin, and SOS notifications always route to
    SHADZ Admin (SAFETY_TELEGRAM_CHAT_ID) -- never a SafetyUser's own
    telegram_chat_id, even when one is configured.
  - Late-checkin notifications: safety_public.submit_check_in claims a
    SafetyLateCheckinAlert exactly once per (user, safety_date) when a
    check-in lands at/after that day's deadline on a day that is not (and
    does not become) SAFE, while S5's locked daily-state rule (MISSED is
    terminal, never rewritten by a later check-in) is left untouched. The
    async notify loop then delivers it to Admin with the same
    claim/retry/idempotency contract as every other S6 notification.

Mirrors the S6 test harness (test_safety_notify_s6.py): an isolated
in-memory SQLite database, no import of main.py,
safety_telegram._send_telegram_message mocked so no real network call is
ever made.
"""
import asyncio
import os
import sys
import unittest
from datetime import date, datetime, time, timedelta, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
import safety_telegram
from database import Base
from safety_deadline import evaluate_user_deadline, resolve_checkin
from safety_notify import (
    DELIVERY_LEASE_SECONDS,
    claim_late_checkin_alert,
    collect_due_late_checkin_alerts,
    mark_late_checkin_notified,
    release_late_checkin_delivery_claim,
)
from safety_public import SafetyGPSPayload, submit_check_in

_ADMIN_CHAT_ID = 999999
_USER_CHAT_ID = 555555


def _run(coro):
    return asyncio.run(coro)


class SafetyTelegramRoutingS61Tests(unittest.TestCase):
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

    def _make_user(self, nfc_token="tok-1", timezone_name="UTC", deadline=time(21, 0),
                    early_reminder_minutes=30, is_active=True, created_at=None,
                    telegram_chat_id=None):
        kwargs = {}
        if created_at is not None:
            kwargs["created_at"] = created_at
        user = models.SafetyUser(
            display_name="Alice",
            timezone=timezone_name,
            daily_deadline=deadline,
            early_reminder_minutes=early_reminder_minutes,
            nfc_token=nfc_token,
            is_active=is_active,
            telegram_chat_id=telegram_chat_id,
            **kwargs,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def _make_checkin(self, user, checked_in_at, latitude=None, longitude=None):
        checkin = models.SafetyCheckIn(
            user_id=user.id,
            checked_in_at=checked_in_at,
            latitude=latitude,
            longitude=longitude,
            source="public_web",
        )
        self.db.add(checkin)
        self.db.commit()
        self.db.refresh(checkin)
        return checkin

    def _patch_send(self, return_value=None, side_effect=None):
        return patch.object(
            safety_telegram, "_send_telegram_message", new_callable=AsyncMock,
            return_value=return_value, side_effect=side_effect,
        )

    # ── early reminder -> SafetyUser's own chat id, never Admin ──────────

    def test_early_reminder_uses_users_own_chat_id(self):
        user = self._make_user(telegram_chat_id=_USER_CHAT_ID)
        with self._patch_send(return_value=True) as mock_send:
            sent = _run(safety_telegram.send_early_reminder(user))
        self.assertTrue(sent)
        mock_send.assert_awaited_once_with(_USER_CHAT_ID, unittest.mock.ANY)

    def test_early_reminder_missing_user_chat_id_fails_and_never_falls_back_to_admin(self):
        user = self._make_user(telegram_chat_id=None)
        with self._patch_send(return_value=True) as mock_send:
            with self.assertLogs("safety_telegram", level="ERROR"):
                sent = _run(safety_telegram.send_early_reminder(user))
        self.assertFalse(sent)
        # Never even reached Telegram -- and critically, never substituted
        # the Admin chat id for the missing user chat id.
        mock_send.assert_not_awaited()

    def test_early_reminder_never_uses_admin_chat_id_even_if_equal_to_admin_env(self):
        # A SafetyUser whose own chat id happens to differ from Admin's
        # proves routing reads telegram_chat_id, not SAFETY_TELEGRAM_CHAT_ID.
        user = self._make_user(telegram_chat_id=_USER_CHAT_ID)
        self.assertNotEqual(_USER_CHAT_ID, _ADMIN_CHAT_ID)
        with self._patch_send(return_value=True) as mock_send:
            _run(safety_telegram.send_early_reminder(user))
        called_chat_id = mock_send.await_args.args[0]
        self.assertEqual(called_chat_id, _USER_CHAT_ID)
        self.assertNotEqual(called_chat_id, _ADMIN_CHAT_ID)

    # ── missed-checkin / SOS -> Admin, never the user's own chat id ──────

    def test_missed_checkin_alert_uses_admin_chat_id_not_users_chat_id(self):
        user = self._make_user(telegram_chat_id=_USER_CHAT_ID)
        state = models.SafetyDailyState(
            user_id=user.id, safety_date=date(2026, 8, 19), status="missed",
            deadline_utc=datetime(2026, 8, 19, 21, 0, tzinfo=timezone.utc),
        )
        with self._patch_send(return_value=True) as mock_send:
            sent = _run(safety_telegram.send_missed_checkin_alert(user, state, None))
        self.assertTrue(sent)
        called_chat_id = mock_send.await_args.args[0]
        self.assertEqual(called_chat_id, _ADMIN_CHAT_ID)
        self.assertNotEqual(called_chat_id, _USER_CHAT_ID)

    def test_sos_uses_admin_chat_id_not_users_chat_id(self):
        user = self._make_user(telegram_chat_id=_USER_CHAT_ID)
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)
        with self._patch_send(return_value=True) as mock_send:
            sent = _run(safety_telegram.send_sos_notification(user, emergency))
        self.assertTrue(sent)
        called_chat_id = mock_send.await_args.args[0]
        self.assertEqual(called_chat_id, _ADMIN_CHAT_ID)
        self.assertNotEqual(called_chat_id, _USER_CHAT_ID)

    def test_missing_admin_chat_id_leaves_missed_alert_retryable(self):
        self._chat_env.stop()
        os.environ.pop("SAFETY_TELEGRAM_CHAT_ID", None)
        try:
            user = self._make_user(telegram_chat_id=_USER_CHAT_ID)
            state = models.SafetyDailyState(
                user_id=user.id, safety_date=date(2026, 8, 19), status="missed",
                deadline_utc=datetime(2026, 8, 19, 21, 0, tzinfo=timezone.utc),
            )
            with self._patch_send(return_value=True) as mock_send:
                sent = _run(safety_telegram.send_missed_checkin_alert(user, state, None))
            self.assertFalse(sent)
            mock_send.assert_not_awaited()
        finally:
            self._chat_env = patch.dict(os.environ, {"SAFETY_TELEGRAM_CHAT_ID": str(_ADMIN_CHAT_ID)})
            self._chat_env.start()

    # ── late-checkin: claim (submit_check_in) ─────────────────────────────
    #
    # submit_check_in's SafetyCheckIn.checked_in_at is always
    # server-generated at insert time (real wall clock, see models.py) --
    # there is no way to inject a fixed clock through the public API. So
    # these tests anchor the deadline a few minutes *before* the real
    # "now" at setup time (matching the technique
    # test_safety_notify_orm_handoff_s6.py already uses) rather than
    # hardcoding a calendar date, which would silently stop testing
    # lateness at all once the real date moves past it.

    def test_late_checkin_on_already_missed_day_is_claimed_once(self):
        now = datetime.now(timezone.utc)
        past_deadline = (now - timedelta(minutes=5)).time()
        user = self._make_user(
            timezone_name="UTC", deadline=past_deadline, created_at=now - timedelta(days=2)
        )
        # No prior check-in exists for today, and its deadline has already
        # passed -- the evaluator resolves it to MISSED (S5 authority,
        # reused as-is, never re-derived here).
        evaluate_user_deadline(self.db, user, now_utc=now)
        today_state = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .order_by(models.SafetyDailyState.safety_date.desc())
            .first()
        )
        self.assertEqual(today_state.status, "missed")

        payload = SafetyGPSPayload(latitude=1.0, longitude=2.0)
        submit_check_in(user.secure_token, payload, self.db)

        alerts = self.db.query(models.SafetyLateCheckinAlert).all()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].user_id, user.id)
        self.assertEqual(alerts[0].safety_date, today_state.safety_date)
        self.assertIsNone(alerts[0].notified_at)

        # S5's locked rule is untouched: MISSED stays terminal.
        row = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.id == today_state.id)
            .first()
        )
        self.assertEqual(row.status, "missed")

    def test_second_late_checkin_same_day_does_not_duplicate_claim(self):
        now = datetime.now(timezone.utc)
        past_deadline = (now - timedelta(minutes=5)).time()
        user = self._make_user(
            timezone_name="UTC", deadline=past_deadline, created_at=now - timedelta(days=2)
        )
        evaluate_user_deadline(self.db, user, now_utc=now)

        payload = SafetyGPSPayload(latitude=1.0, longitude=2.0)
        submit_check_in(user.secure_token, payload, self.db)
        submit_check_in(user.secure_token, payload, self.db)

        alerts = self.db.query(models.SafetyLateCheckinAlert).all()
        self.assertEqual(len(alerts), 1)

    def test_claim_does_not_commit_outer_transaction(self):
        # Regression: claim_late_checkin_alert() previously called
        # db.commit() itself, which prematurely committed submit_check_in's
        # whole transaction (the SafetyCheckIn insert and any
        # SafetyDailyState change) the moment a late check-in was claimed --
        # giving the first claim (new row -> commit branch) different
        # transaction semantics than a duplicate claim (existing row -> no
        # commit branch). This replicates submit_check_in's exact
        # transaction shape directly (insert check-in, resolve_checkin,
        # claim_late_checkin_alert) but never reaches a final commit --
        # simulating a crash/exception in submit_check_in after the claim --
        # and proves the check-in, the freshly-created SafetyDailyState row,
        # and the late-checkin claim all roll back together as one atomic
        # unit, because claim_late_checkin_alert only flushes.
        now = datetime.now(timezone.utc)
        past_deadline = (now - timedelta(minutes=5)).time()
        user = self._make_user(
            timezone_name="UTC", deadline=past_deadline, created_at=now - timedelta(days=2)
        )
        # No SafetyDailyState row exists yet for today at all -- so
        # resolve_checkin's get_or_create_daily_state below creates a brand
        # new (uncommitted) row, not merely mutating an existing one.
        self.assertEqual(
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .count(),
            0,
        )

        check_in = models.SafetyCheckIn(
            user_id=user.id, latitude=1.0, longitude=2.0, source="public_web"
        )
        self.db.add(check_in)
        self.db.flush()
        daily_state = resolve_checkin(self.db, user, check_in)
        # Late (checked_in_at is now, well after the past deadline), so
        # resolve_checkin leaves it pending -- S5 punts late resolution to
        # the evaluator, never to resolve_checkin itself.
        self.assertEqual(daily_state.status, "pending")

        claim_late_checkin_alert(self.db, user.id, daily_state.safety_date, check_in.id)

        # Never reach submit_check_in's own final db.commit() -- simulating
        # a failure between the claim and that commit.
        self.db.rollback()

        self.assertEqual(
            self.db.query(models.SafetyCheckIn)
            .filter(models.SafetyCheckIn.user_id == user.id)
            .count(),
            0,
        )
        self.assertEqual(
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .count(),
            0,
        )
        self.assertEqual(self.db.query(models.SafetyLateCheckinAlert).count(), 0)

    def test_on_time_checkin_never_claimed_as_late(self):
        # Deadline set to the last minute of the UTC day so "now" (real
        # wall-clock, since submit_check_in's checked_in_at is always
        # server-generated) is on-time for the entire test run -- same
        # convention test_safety_checkin_submission_s4.py already relies on
        # for its own future-deadline check-in tests.
        user = self._make_user(timezone_name="UTC", deadline=time(23, 59))
        payload = SafetyGPSPayload(latitude=1.0, longitude=2.0)
        submit_check_in(user.secure_token, payload, self.db)

        alerts = self.db.query(models.SafetyLateCheckinAlert).all()
        self.assertEqual(len(alerts), 0)
        row = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .first()
        )
        self.assertEqual(row.status, "safe")

    def test_late_checkin_after_day_already_safe_not_claimed(self):
        # First check-in is genuinely on-time (deadline safely in the
        # future) and resolves the day to SAFE via resolve_checkin itself
        # (S5 behavior, unchanged).
        user = self._make_user(timezone_name="UTC", deadline=time(23, 59))
        payload = SafetyGPSPayload(latitude=1.0, longitude=2.0)
        submit_check_in(user.secure_token, payload, self.db)

        row = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .first()
        )
        self.assertEqual(row.status, "safe")

        # Move that same day's persisted deadline into the past so the
        # SECOND check-in below genuinely lands at/after the deadline --
        # exercising the actual post-deadline branch of submit_check_in's
        # lateness check (checked_in_at >= deadline_utc), not merely a fast
        # second submission that happens to still be comfortably on-time.
        # submit_check_in's SafetyCheckIn.checked_in_at is always
        # server-generated real wall-clock time (see models.py), so there is
        # no way to inject a fixed clock through the public API -- moving
        # the already-persisted deadline_utc backward is the clean way to
        # make "now" genuinely late relative to it.
        row.deadline_utc = datetime.now(timezone.utc) - timedelta(minutes=1)
        self.db.commit()

        # A second same-day submission after the day is already SAFE must
        # never be flagged as a late check-in for Admin, even though it is
        # now genuinely at/after the (moved-back) deadline.
        submit_check_in(user.secure_token, payload, self.db)

        alerts = self.db.query(models.SafetyLateCheckinAlert).all()
        self.assertEqual(len(alerts), 0)
        row = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .first()
        )
        self.assertEqual(row.status, "safe")

    # ── late-checkin: deliver (collect_due / send / retry) to Admin ──────

    def test_late_checkin_alert_delivers_to_admin_chat_id(self):
        user = self._make_user(telegram_chat_id=_USER_CHAT_ID)
        checkin = self._make_checkin(user, datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc))
        claim_late_checkin_alert(self.db, user.id, date(2026, 8, 19), checkin.id)

        now = datetime(2026, 8, 19, 22, 5, tzinfo=timezone.utc)
        due = collect_due_late_checkin_alerts(self.db, now)
        self.assertEqual(len(due), 1)
        due_user, due_checkin, alert, claim_at = due[0]
        self.assertEqual(due_checkin.id, checkin.id)

        with self._patch_send(return_value=True) as mock_send:
            sent = _run(safety_telegram.send_late_checkin_alert(due_user, due_checkin, alert))
        self.assertTrue(sent)
        called_chat_id = mock_send.await_args.args[0]
        self.assertEqual(called_chat_id, _ADMIN_CHAT_ID)
        self.assertTrue(mark_late_checkin_notified(self.db, alert.id, now, claim_at))

        # Not selected again once delivered.
        self.assertEqual(collect_due_late_checkin_alerts(self.db, now + timedelta(minutes=5)), [])

    def test_late_checkin_delivery_failure_remains_retryable(self):
        user = self._make_user()
        checkin = self._make_checkin(user, datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc))
        claim_late_checkin_alert(self.db, user.id, date(2026, 8, 19), checkin.id)

        now = datetime(2026, 8, 19, 22, 5, tzinfo=timezone.utc)
        due_first = collect_due_late_checkin_alerts(self.db, now)
        self.assertEqual(len(due_first), 1)
        due_user, due_checkin, alert, claim_at = due_first[0]

        with self._patch_send(side_effect=RuntimeError("network exploded")):
            sent = _run(safety_telegram.send_late_checkin_alert(due_user, due_checkin, alert))
        self.assertFalse(sent)
        self.assertTrue(release_late_checkin_delivery_claim(self.db, alert.id, claim_at))

        row = (
            self.db.query(models.SafetyLateCheckinAlert)
            .filter(models.SafetyLateCheckinAlert.id == alert.id)
            .first()
        )
        self.assertIsNone(row.notified_at)
        self.assertIsNone(row.delivery_claimed_at)

        due_second = collect_due_late_checkin_alerts(self.db, now + timedelta(minutes=1))
        self.assertEqual(len(due_second), 1)
        self.assertEqual(due_second[0][2].id, alert.id)
        self.assertEqual(self.db.query(models.SafetyLateCheckinAlert).count(), 1)

    def test_abandoned_late_checkin_lease_expires_and_becomes_retryable(self):
        user = self._make_user()
        checkin = self._make_checkin(user, datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc))
        claim_late_checkin_alert(self.db, user.id, date(2026, 8, 19), checkin.id)

        now = datetime(2026, 8, 19, 22, 5, tzinfo=timezone.utc)
        due_first = collect_due_late_checkin_alerts(self.db, now)
        self.assertEqual(len(due_first), 1)
        alert_id = due_first[0][2].id
        # Simulate a crashed worker: lease never released.

        still_leased = now + timedelta(seconds=DELIVERY_LEASE_SECONDS - 5)
        self.assertEqual(collect_due_late_checkin_alerts(self.db, still_leased), [])

        expired = now + timedelta(seconds=DELIVERY_LEASE_SECONDS + 5)
        due_second = collect_due_late_checkin_alerts(self.db, expired)
        self.assertEqual(len(due_second), 1)
        self.assertEqual(due_second[0][2].id, alert_id)

    def test_inactive_user_late_checkin_not_delivered(self):
        user = self._make_user(is_active=False)
        checkin = self._make_checkin(user, datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc))
        claim_late_checkin_alert(self.db, user.id, date(2026, 8, 19), checkin.id)

        now = datetime(2026, 8, 19, 22, 5, tzinfo=timezone.utc)
        self.assertEqual(collect_due_late_checkin_alerts(self.db, now), [])


if __name__ == "__main__":
    unittest.main()
