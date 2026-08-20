"""Regression tests for Safety Engine v1 Phase S6 (Telegram Reminder +
Missed Alert + SOS Escalation — safety_notify.py + safety_telegram.py),
including:
  - the delivery-retry correction: a SafetyAlert/SafetyEmergency claim and a
    confirmed-successful Telegram delivery are two separate facts, so a
    Telegram failure (or a missing SAFETY_TELEGRAM_CHAT_ID) must leave the
    notification retryable on the next tick rather than losing it.
  - the concurrency correction: "eligible for delivery" and "reserved for
    delivery by this worker" are ALSO two separate facts, enforced by a
    short-lived delivery lease (SafetyAlert.delivery_claimed_at /
    SafetyEmergency.notification_claimed_at) so two independent collectors
    can never both pick the same row.
  - the lease-ownership correction: release_*/mark_*_notified only ever act
    on a lease if the caller's expected_claimed_at still matches the
    persisted delivery_claimed_at/notification_claimed_at -- so a stale
    worker whose lease already expired and was reclaimed by someone else
    can never release or mark success for that newer claim.

Most tests mirror the S4/S5 test harness: an isolated in-memory SQLite
database, no import of main.py, safety_telegram._send_telegram_message
mocked so no real network calls are ever made.

SafetyNotifyConcurrencyTests below deliberately does NOT use a single
shared Session called twice — it uses two independent SQLAlchemy engines
and Sessions against the same on-disk SQLite file, which is what actually
exercises the atomic-UPDATE claim contract the lease relies on.
"""
import asyncio
import os
import sys
import tempfile
import unittest
from datetime import date, datetime, time, timedelta, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import bot_runtime
import models
import safety_telegram
from database import Base
from safety_deadline import evaluate_user_deadline, resolve_checkin
from safety_notify import (
    DELIVERY_LEASE_SECONDS,
    SOS_RETRY_INTERVAL_SECONDS,
    collect_due_early_reminders,
    collect_due_missed_alerts,
    collect_due_sos_notifications,
    last_checkin_before,
    mark_alert_notified,
    mark_sos_notified,
    release_alert_delivery_claim,
    release_sos_delivery_claim,
)


def _run(coro):
    return asyncio.run(coro)


class SafetyNotifyS6Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

        self._chat_env = patch.dict(os.environ, {"SAFETY_TELEGRAM_CHAT_ID": "999999"})
        self._chat_env.start()

    def tearDown(self):
        self._chat_env.stop()
        self.db.close()

    def _make_user(self, nfc_token="tok-1", timezone_name="UTC", deadline=time(21, 0),
                    early_reminder_minutes=30, is_active=True, created_at=None,
                    telegram_chat_id=777777):
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
        """Patch the low-level Safety sender directly (rather than
        bot_runtime._send_message, which cannot signal success/failure at
        all) so tests can simulate a confirmed success or a confirmed
        failure/exception precisely."""
        return patch.object(
            safety_telegram, "_send_telegram_message", new_callable=AsyncMock,
            return_value=return_value, side_effect=side_effect,
        )

    # ── early reminder ────────────────────────────────────────────────

    def test_early_reminder_before_trigger_time_none(self):
        self._make_user(deadline=time(21, 0), early_reminder_minutes=30)
        now = datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc)
        due = collect_due_early_reminders(self.db, now)
        self.assertEqual(due, [])
        self.assertEqual(self.db.query(models.SafetyAlert).count(), 0)

    def test_early_reminder_at_trigger_fires_exactly_once_after_success(self):
        user = self._make_user(deadline=time(21, 0), early_reminder_minutes=30)
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)

        due_first = collect_due_early_reminders(self.db, trigger_at)
        self.assertEqual(len(due_first), 1)
        due_user, alert, claim_at = due_first[0]
        self.assertIsNone(alert.notified_at)
        self.assertIsNotNone(claim_at)

        with self._patch_send(return_value=True) as mock_send:
            sent = _run(safety_telegram.send_early_reminder(due_user))
        self.assertTrue(sent)
        mock_send.assert_awaited_once()
        self.assertTrue(mark_alert_notified(self.db, alert.id, trigger_at, claim_at))

        # A later tick (still same pending day) must not re-fire once
        # successfully delivered.
        due_second = collect_due_early_reminders(self.db, trigger_at + timedelta(minutes=5))
        self.assertEqual(due_second, [])
        self.assertEqual(
            self.db.query(models.SafetyAlert)
            .filter(models.SafetyAlert.alert_type == "early_reminder")
            .count(),
            1,
        )

    def test_safe_day_produces_no_reminder(self):
        user = self._make_user(deadline=time(21, 0), early_reminder_minutes=30)
        checkin_at = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)
        self._make_checkin(user, checkin_at)
        evaluate_user_deadline(self.db, user, now_utc=checkin_at)
        checkin = (
            self.db.query(models.SafetyCheckIn)
            .filter(models.SafetyCheckIn.user_id == user.id)
            .first()
        )
        resolve_checkin(self.db, user, checkin)
        self.db.commit()

        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)
        due = collect_due_early_reminders(self.db, trigger_at)
        self.assertEqual(due, [])
        self.assertEqual(
            self.db.query(models.SafetyAlert)
            .filter(models.SafetyAlert.alert_type == "early_reminder")
            .count(),
            0,
        )

    # ── delivery-retry correction: one-shot alerts ──────────────────────

    def test_early_reminder_telegram_failure_remains_retryable(self):
        user = self._make_user(deadline=time(21, 0), early_reminder_minutes=30)
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)

        due_first = collect_due_early_reminders(self.db, trigger_at)
        self.assertEqual(len(due_first), 1)
        due_user, alert, claim_at = due_first[0]

        with self._patch_send(return_value=False):
            sent = _run(safety_telegram.send_early_reminder(due_user))
        self.assertFalse(sent)
        # Caller (main.py's _deliver_early_reminder) releases the delivery
        # lease on a False send instead of marking notified -- simulate
        # that contract explicitly, threading through the exact claim_at
        # this call won.
        self.assertTrue(release_alert_delivery_claim(self.db, alert.id, claim_at))

        row = self.db.query(models.SafetyAlert).filter(models.SafetyAlert.id == alert.id).first()
        self.assertIsNone(row.notified_at)
        self.assertIsNone(row.delivery_claimed_at)

        # The very next tick must still find it due.
        due_second = collect_due_early_reminders(self.db, trigger_at + timedelta(minutes=1))
        self.assertEqual(len(due_second), 1)
        self.assertEqual(due_second[0][1].id, alert.id)
        # Still only one logical alert row -- retried, not duplicated.
        self.assertEqual(
            self.db.query(models.SafetyAlert)
            .filter(models.SafetyAlert.alert_type == "early_reminder")
            .count(),
            1,
        )

    def test_missed_alert_telegram_failure_remains_retryable(self):
        user = self._make_user(
            deadline=time(21, 0), created_at=datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc)
        )
        past_deadline = datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc)
        evaluate_user_deadline(self.db, user, now_utc=past_deadline)

        due_first = collect_due_missed_alerts(self.db, past_deadline)
        self.assertEqual(len(due_first), 1)
        due_user, daily_state, alert, claim_at = due_first[0]

        with self._patch_send(side_effect=RuntimeError("network exploded")):
            sent = _run(safety_telegram.send_missed_checkin_alert(due_user, daily_state, None))
        self.assertFalse(sent)  # _send catches the exception and returns False
        self.assertTrue(release_alert_delivery_claim(self.db, alert.id, claim_at))

        row = self.db.query(models.SafetyAlert).filter(models.SafetyAlert.id == alert.id).first()
        self.assertIsNone(row.notified_at)
        self.assertIsNone(row.delivery_claimed_at)

        due_second = collect_due_missed_alerts(self.db, past_deadline + timedelta(minutes=10))
        self.assertEqual(len(due_second), 1)
        self.assertEqual(due_second[0][2].id, alert.id)
        self.assertEqual(
            self.db.query(models.SafetyAlert)
            .filter(models.SafetyAlert.alert_type == "missed_checkin")
            .count(),
            1,
        )

    def test_missing_user_chat_id_leaves_reminder_retryable(self):
        # Phase S6.1: early reminder routes to the SafetyUser's own
        # telegram_chat_id, not SAFETY_TELEGRAM_CHAT_ID -- a missing *user*
        # chat id (independent of the Admin env var, which stays set here)
        # is what must fail closed and stay retryable now. See
        # tests/test_safety_telegram_routing_s6_1.py for the full S6.1
        # recipient-routing suite.
        user = self._make_user(deadline=time(21, 0), early_reminder_minutes=30, telegram_chat_id=None)
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)
        due_first = collect_due_early_reminders(self.db, trigger_at)
        due_user, alert, claim_at = due_first[0]

        with self._patch_send(return_value=True) as mock_send:
            sent = _run(safety_telegram.send_early_reminder(due_user))
        self.assertFalse(sent)
        mock_send.assert_not_awaited()  # never even reached Telegram
        self.assertTrue(release_alert_delivery_claim(self.db, alert.id, claim_at))

        row = self.db.query(models.SafetyAlert).filter(models.SafetyAlert.id == alert.id).first()
        self.assertIsNone(row.notified_at)
        due_second = collect_due_early_reminders(self.db, trigger_at + timedelta(minutes=1))
        self.assertEqual(len(due_second), 1)

    def test_successful_one_shot_send_has_no_later_duplicate(self):
        user = self._make_user(deadline=time(21, 0), early_reminder_minutes=30)
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)
        due_first = collect_due_early_reminders(self.db, trigger_at)
        due_user, alert, claim_at = due_first[0]

        with self._patch_send(return_value=True):
            sent = _run(safety_telegram.send_early_reminder(due_user))
        self.assertTrue(sent)
        marked = mark_alert_notified(self.db, alert.id, trigger_at, claim_at)
        self.assertTrue(marked)

        # A duplicate mark call (e.g. a racing/duplicate tick reusing the
        # same claim_at) is a no-op -- notified_at is no longer NULL.
        marked_again = mark_alert_notified(self.db, alert.id, trigger_at + timedelta(seconds=1), claim_at)
        self.assertFalse(marked_again)

        for later in (trigger_at, trigger_at + timedelta(hours=1)):
            self.assertEqual(collect_due_early_reminders(self.db, later), [])
        self.assertEqual(
            self.db.query(models.SafetyAlert)
            .filter(models.SafetyAlert.alert_type == "early_reminder")
            .count(),
            1,
        )

    def test_unique_logical_alert_guarantee_still_intact(self):
        user = self._make_user()
        self.db.add(models.SafetyAlert(
            user_id=user.id, safety_date=date(2026, 8, 19), alert_type="early_reminder",
        ))
        self.db.commit()
        from sqlalchemy.exc import IntegrityError
        self.db.add(models.SafetyAlert(
            user_id=user.id, safety_date=date(2026, 8, 19), alert_type="early_reminder",
        ))
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_missed_alert_includes_last_known_checkin_and_location(self):
        user = self._make_user(
            deadline=time(21, 0), created_at=datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc)
        )
        prior_checkin = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)
        self._make_checkin(user, prior_checkin, latitude=40.7128, longitude=-74.0060)

        past_deadline = datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc)
        evaluate_user_deadline(self.db, user, now_utc=past_deadline)
        row = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .first()
        )
        last_checkin = last_checkin_before(self.db, user.id, row.deadline_utc)
        self.assertIsNotNone(last_checkin)
        message = safety_telegram._format_missed_checkin(user, row, last_checkin)
        self.assertIn("40.7128", message)
        self.assertIn("maps.google.com", message)

    # ── S5 state must never be touched by Telegram outcomes ─────────────

    def test_telegram_send_failure_does_not_corrupt_alert_or_daily_state(self):
        user = self._make_user(deadline=time(21, 0), early_reminder_minutes=30)
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)
        due = collect_due_early_reminders(self.db, trigger_at)
        self.assertEqual(len(due), 1)
        due_user, _alert, _claim_at = due[0]

        with self._patch_send(side_effect=RuntimeError("network exploded")):
            sent = _run(safety_telegram.send_early_reminder(due_user))
        self.assertFalse(sent)

        self.assertEqual(
            self.db.query(models.SafetyAlert)
            .filter(models.SafetyAlert.alert_type == "early_reminder")
            .count(),
            1,
        )
        row = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .first()
        )
        self.assertEqual(row.status, "pending")

    def test_s5_evaluator_unaffected_by_s6_module(self):
        now = datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc)
        user = self._make_user(deadline=time(21, 0), created_at=now - timedelta(days=1))
        row = evaluate_user_deadline(self.db, user, now_utc=now)
        self.assertEqual(row.status, "pending")

    # ── SOS escalation ────────────────────────────────────────────────

    def test_sos_persists_independently_of_telegram_success(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(
            user_id=user.id, latitude=1.0, longitude=2.0, status="open",
        )
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)

        with self._patch_send(side_effect=RuntimeError("telegram down")):
            sent = _run(safety_telegram.send_sos_notification(user, emergency))
        self.assertFalse(sent)

        persisted = (
            self.db.query(models.SafetyEmergency).filter(models.SafetyEmergency.id == emergency.id).first()
        )
        self.assertIsNotNone(persisted)
        self.assertEqual(persisted.status, "open")

    def test_open_sos_is_due_for_notification_immediately(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, latitude=1.0, longitude=2.0, status="open")
        self.db.add(emergency)
        self.db.commit()

        now = datetime.now(timezone.utc)
        due = collect_due_sos_notifications(self.db, now)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0][0].id, user.id)
        self.assertIsNotNone(due[0][2])

    def test_sos_telegram_failure_leaves_last_notified_at_unchanged(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)

        with self._patch_send(return_value=False):
            sent = _run(safety_telegram.send_sos_notification(user, emergency))
        self.assertFalse(sent)
        # Caller only calls mark_sos_notified on success -- not called here.

        row = self.db.query(models.SafetyEmergency).filter(models.SafetyEmergency.id == emergency.id).first()
        self.assertIsNone(row.last_notified_at)

    def test_failed_sos_is_eligible_again_on_next_notify_tick(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db.add(emergency)
        self.db.commit()

        now = datetime.now(timezone.utc)
        first = collect_due_sos_notifications(self.db, now)
        self.assertEqual(len(first), 1)
        due_user, due_emergency, claim_at = first[0]

        with self._patch_send(return_value=False):
            sent = _run(safety_telegram.send_sos_notification(due_user, due_emergency))
        self.assertFalse(sent)
        # main.py's _deliver_sos_notification releases the lease on a
        # False send -- simulate that explicitly, threading through the
        # exact claim_at this call won.
        self.assertTrue(release_sos_delivery_claim(self.db, due_emergency.id, claim_at))

        # No cooldown applies -- a failed send never started one, and the
        # lease is released, so the very next tick sees it due again.
        again = collect_due_sos_notifications(self.db, now + timedelta(seconds=1))
        self.assertEqual(len(again), 1)

    def test_successful_sos_updates_last_notified_at(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)

        now = datetime.now(timezone.utc)
        due = collect_due_sos_notifications(self.db, now)
        self.assertEqual(len(due), 1)
        due_user, due_emergency, claim_at = due[0]

        with self._patch_send(return_value=True):
            sent = _run(safety_telegram.send_sos_notification(due_user, due_emergency))
        self.assertTrue(sent)
        marked = mark_sos_notified(self.db, due_emergency.id, now, claim_at)
        self.assertTrue(marked)

        row = self.db.query(models.SafetyEmergency).filter(models.SafetyEmergency.id == emergency.id).first()
        self.assertIsNotNone(row.last_notified_at)
        self.assertIsNone(row.notification_claimed_at)

    def test_successful_sos_not_due_before_retry_interval(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)

        now = datetime.now(timezone.utc)
        due = collect_due_sos_notifications(self.db, now)
        self.assertEqual(len(due), 1)
        _due_user, due_emergency, claim_at = due[0]
        self.assertTrue(mark_sos_notified(self.db, due_emergency.id, now, claim_at))

        soon = now + timedelta(seconds=SOS_RETRY_INTERVAL_SECONDS - 5)
        self.assertEqual(collect_due_sos_notifications(self.db, soon), [])

        later = now + timedelta(seconds=SOS_RETRY_INTERVAL_SECONDS + 5)
        retried = collect_due_sos_notifications(self.db, later)
        self.assertEqual(len(retried), 1)

    def test_mark_sos_notified_guards_against_resolved_status(self):
        # Phase S7 locked the final escalation-eligibility rule: 'resolved'
        # is the only status that stops escalation -- 'acknowledged' alone
        # must not (see tests/test_safety_sos_lifecycle_s7.py). This test
        # originally asserted the opposite for 'acknowledged'; updated here
        # to assert the actual locked S7 behavior instead.
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="resolved")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)

        # Never claimed (not open/acknowledged, so
        # collect_due_sos_notifications would never select it -- see
        # test_resolved_sos_no_longer_selected). notification_claimed_at is
        # still NULL here; passing None proves the status guard alone
        # rejects this, independent of any lease mismatch.
        marked = mark_sos_notified(self.db, emergency.id, datetime.now(timezone.utc), None)
        self.assertFalse(marked)
        row = self.db.query(models.SafetyEmergency).filter(models.SafetyEmergency.id == emergency.id).first()
        self.assertIsNone(row.last_notified_at)

    def test_resolved_sos_no_longer_selected(self):
        # Phase S7: escalation stops only once status == 'resolved' -- see
        # test_safety_sos_lifecycle_s7.py for the full acknowledge/resolve
        # lifecycle coverage, including that 'acknowledged' alone must NOT
        # stop escalation (that used to be asserted here as
        # test_acknowledged_sos_no_longer_selected).
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="resolved")
        self.db.add(emergency)
        self.db.commit()

        due = collect_due_sos_notifications(self.db, datetime.now(timezone.utc))
        self.assertEqual(due, [])

    # ── isolation: one failure must not block another due notification ──

    def test_one_failed_send_does_not_prevent_another_due_send(self):
        # sos_user is deliberately inactive so it can never also match
        # collect_due_early_reminders's default deadline/early_reminder_minutes
        # -- keeps the two due lists below unambiguous.
        reminder_user = self._make_user(nfc_token="tok-reminder", deadline=time(21, 0), early_reminder_minutes=30)
        sos_user = self._make_user(nfc_token="tok-sos", is_active=False)
        emergency = models.SafetyEmergency(user_id=sos_user.id, status="open")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)

        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)
        due_reminders = collect_due_early_reminders(self.db, trigger_at)
        # SOS eligibility is independent of SafetyUser.is_active -- an SOS
        # is a real, already-persisted emergency regardless of the user's
        # active flag, so this is deliberately not filtered by it.
        due_sos = collect_due_sos_notifications(self.db, trigger_at)
        self.assertEqual(len(due_reminders), 1)
        self.assertEqual(due_reminders[0][0].id, reminder_user.id)
        self.assertEqual(len(due_sos), 1)
        self.assertEqual(due_sos[0][0].id, sos_user.id)

        # Simulate main.py's per-item batch loop: the first send raises,
        # the second must still be attempted and can still succeed.
        with self._patch_send(side_effect=[RuntimeError("boom"), True]) as mock_send:
            reminder_sent = _run(safety_telegram.send_early_reminder(due_reminders[0][0]))
            sos_sent = _run(safety_telegram.send_sos_notification(due_sos[0][0], due_sos[0][1]))

        self.assertFalse(reminder_sent)  # exception -> caught -> False, never raised
        self.assertTrue(sos_sent)
        self.assertEqual(mock_send.await_count, 2)

    # ── GPS / Maps content only when persisted ──────────────────────────

    def test_maps_link_present_only_with_persisted_coordinates(self):
        self.assertIsNone(safety_telegram.maps_link(None, None))
        self.assertIsNone(safety_telegram.maps_link(1.0, None))
        self.assertIsNone(safety_telegram.maps_link(None, 1.0))
        link = safety_telegram.maps_link(1.0, 2.0)
        self.assertEqual(link, "https://maps.google.com/?q=1.0,2.0")

    def test_sos_message_never_fabricates_location(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)
        message = safety_telegram._format_sos(user, emergency)
        self.assertIn("not available", message)
        self.assertNotIn("maps.google.com", message)

    # ── inactive users ──────────────────────────────────────────────────

    def test_inactive_user_not_processed_for_reminder_or_missed_alert(self):
        user = self._make_user(deadline=time(21, 0), early_reminder_minutes=30, is_active=False)
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)
        self.assertEqual(collect_due_early_reminders(self.db, trigger_at), [])

        past_deadline = datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc)
        state = models.SafetyDailyState(
            user_id=user.id, safety_date=date(2026, 8, 19), status="missed",
            deadline_utc=datetime(2026, 8, 19, 21, 0, tzinfo=timezone.utc),
        )
        self.db.add(state)
        self.db.commit()
        self.assertEqual(collect_due_missed_alerts(self.db, past_deadline), [])
        self.assertEqual(self.db.query(models.SafetyAlert).count(), 0)


_FAKE_TELEGRAM_TOKEN = "123456:FAKE-TOKEN-DO-NOT-USE-abcdefgh"


class SafetyTelegramResponseContractTests(unittest.TestCase):
    """Exercises the real safety_telegram._send_telegram_message body (not
    mocked) against a mocked httpx.AsyncClient, so no real network call is
    ever possible while still covering the actual Telegram Bot API
    ok:true/false JSON-body contract enforcement -- a 2xx HTTP status alone
    must never be treated as confirmed delivery."""

    def setUp(self):
        self._token_patcher = patch.dict(os.environ, {"TELEGRAM_BOT_TOKEN": _FAKE_TELEGRAM_TOKEN})
        self._token_patcher.start()

    def tearDown(self):
        self._token_patcher.stop()

    def _mock_client_for(self, response):
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.post = AsyncMock(return_value=response)
        return mock_client

    def _send_message_url(self):
        return bot_runtime._TELEGRAM_API_BASE.format(token=_FAKE_TELEGRAM_TOKEN) + "/sendMessage"

    def test_http_200_with_ok_true_is_confirmed_success(self):
        request = httpx.Request("POST", self._send_message_url())
        response = httpx.Response(200, request=request, json={"ok": True, "result": {"message_id": 1}})
        mock_client = self._mock_client_for(response)

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            sent = asyncio.run(safety_telegram._send_telegram_message(42, "hello"))
        self.assertTrue(sent)

    def test_http_200_with_ok_false_is_not_confirmed(self):
        request = httpx.Request("POST", self._send_message_url())
        response = httpx.Response(
            200, request=request, json={"ok": False, "description": "chat not found"}
        )
        mock_client = self._mock_client_for(response)

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            with self.assertLogs("safety_telegram", level="ERROR"):
                sent = asyncio.run(safety_telegram._send_telegram_message(42, "hello"))
        self.assertFalse(sent)

    def test_http_200_with_malformed_body_is_not_confirmed(self):
        request = httpx.Request("POST", self._send_message_url())
        response = httpx.Response(200, request=request, content=b"not json at all")
        mock_client = self._mock_client_for(response)

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            with self.assertLogs("safety_telegram", level="ERROR") as captured:
                sent = asyncio.run(safety_telegram._send_telegram_message(42, "hello"))
        self.assertFalse(sent)
        # Never leak the token/full request URL, matching
        # bot_runtime._send_message's identical guard.
        log_output = "\n".join(captured.output)
        self.assertNotIn(_FAKE_TELEGRAM_TOKEN, log_output)
        self.assertNotIn(f"/bot{_FAKE_TELEGRAM_TOKEN}/", log_output)

    def test_http_status_error_still_returns_false(self):
        request = httpx.Request("POST", self._send_message_url())
        response = httpx.Response(
            401, request=request, json={"ok": False, "description": "Unauthorized"}
        )
        mock_client = self._mock_client_for(response)

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            with self.assertLogs("safety_telegram", level="ERROR") as captured:
                sent = asyncio.run(safety_telegram._send_telegram_message(42, "hello"))
        self.assertFalse(sent)
        log_output = "\n".join(captured.output)
        self.assertIn("401", log_output)
        self.assertNotIn(_FAKE_TELEGRAM_TOKEN, log_output)
        self.assertNotIn(f"/bot{_FAKE_TELEGRAM_TOKEN}/", log_output)
        self.assertNotIn("api.telegram.org", log_output)

    def test_network_error_still_returns_false(self):
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("connection refused"))

        with patch.object(httpx, "AsyncClient", return_value=mock_client):
            with self.assertLogs("safety_telegram", level="ERROR"):
                sent = asyncio.run(safety_telegram._send_telegram_message(42, "hello"))
        self.assertFalse(sent)


class SafetyNotifyConcurrencyTests(unittest.TestCase):
    """Proves the S6 delivery lease and lease-ownership guarantees using
    two genuinely independent SQLAlchemy Sessions -- separate engines/
    connections -- against the same on-disk SQLite database file. This is
    deliberately NOT two sequential calls through one shared Session: the
    whole point of the lease is that the claim is an atomic UPDATE
    evaluated by SQLite itself, so exercising it through two real,
    independent connections is what actually proves the guarantee holds
    under concurrent/independent workers rather than just "the same Python
    object called twice."
    """

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".sqlite3")
        os.close(fd)

        self.engine_a = create_engine(f"sqlite:///{self.db_path}", connect_args={"timeout": 30})
        Base.metadata.create_all(bind=self.engine_a)
        self.engine_b = create_engine(f"sqlite:///{self.db_path}", connect_args={"timeout": 30})

        SessionA = sessionmaker(bind=self.engine_a, autocommit=False, autoflush=False)
        SessionB = sessionmaker(bind=self.engine_b, autocommit=False, autoflush=False)
        self.db_a = SessionA()
        self.db_b = SessionB()

        self._chat_env = patch.dict(os.environ, {"SAFETY_TELEGRAM_CHAT_ID": "999999"})
        self._chat_env.start()

    def tearDown(self):
        self._chat_env.stop()
        self.db_a.close()
        self.db_b.close()
        self.engine_a.dispose()
        self.engine_b.dispose()
        os.unlink(self.db_path)

    def _make_user(self, session, nfc_token, **overrides):
        defaults = dict(
            display_name="Alice",
            timezone="UTC",
            daily_deadline=time(21, 0),
            early_reminder_minutes=30,
            nfc_token=nfc_token,
            telegram_chat_id=777777,
        )
        defaults.update(overrides)
        user = models.SafetyUser(**defaults)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user

    def test_two_sessions_cannot_both_claim_same_early_reminder(self):
        self._make_user(self.db_a, nfc_token="tok-conc-reminder")
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)

        due_a = collect_due_early_reminders(self.db_a, trigger_at)
        due_b = collect_due_early_reminders(self.db_b, trigger_at)

        self.assertEqual(len(due_a), 1)
        self.assertEqual(due_b, [])  # session_b's claim UPDATE matched zero rows

    def test_two_sessions_cannot_both_claim_same_missed_alert(self):
        user = self._make_user(
            self.db_a, nfc_token="tok-conc-missed",
            created_at=datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc),
        )
        past_deadline = datetime(2026, 8, 19, 22, 0, tzinfo=timezone.utc)
        evaluate_user_deadline(self.db_a, user, now_utc=past_deadline)

        due_a = collect_due_missed_alerts(self.db_a, past_deadline)
        due_b = collect_due_missed_alerts(self.db_b, past_deadline)

        self.assertEqual(len(due_a), 1)
        self.assertEqual(due_b, [])

    def test_two_sessions_cannot_both_claim_same_sos(self):
        user = self._make_user(self.db_a, nfc_token="tok-conc-sos")
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db_a.add(emergency)
        self.db_a.commit()

        now = datetime.now(timezone.utc)
        due_a = collect_due_sos_notifications(self.db_a, now)
        due_b = collect_due_sos_notifications(self.db_b, now)

        self.assertEqual(len(due_a), 1)
        self.assertEqual(due_b, [])

    def test_failed_send_release_makes_lease_immediately_retryable_across_sessions(self):
        self._make_user(self.db_a, nfc_token="tok-conc-release")
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)

        due_a = collect_due_early_reminders(self.db_a, trigger_at)
        self.assertEqual(len(due_a), 1)
        _due_user, alert, claim_at = due_a[0]

        # Session A's send failed; it releases the lease (main.py's
        # _deliver_early_reminder path on a False send) using the exact
        # claim_at it won.
        self.assertTrue(release_alert_delivery_claim(self.db_a, alert.id, claim_at))

        # A completely independent session's very next tick must see it
        # due again immediately -- no waiting out DELIVERY_LEASE_SECONDS.
        due_b = collect_due_early_reminders(self.db_b, trigger_at + timedelta(seconds=1))
        self.assertEqual(len(due_b), 1)
        self.assertEqual(due_b[0][1].id, alert.id)

    def test_abandoned_lease_expires_and_becomes_retryable_across_sessions(self):
        self._make_user(self.db_a, nfc_token="tok-conc-crash")
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)

        due_a = collect_due_early_reminders(self.db_a, trigger_at)
        self.assertEqual(len(due_a), 1)
        alert_id = due_a[0][1].id
        # Simulate session A's worker crashing mid-delivery: the claim is
        # never released.

        still_leased = trigger_at + timedelta(seconds=DELIVERY_LEASE_SECONDS - 5)
        self.assertEqual(collect_due_early_reminders(self.db_b, still_leased), [])

        expired = trigger_at + timedelta(seconds=DELIVERY_LEASE_SECONDS + 5)
        due_b = collect_due_early_reminders(self.db_b, expired)
        self.assertEqual(len(due_b), 1)
        self.assertEqual(due_b[0][1].id, alert_id)

    def test_successful_delivery_not_selected_again_across_sessions(self):
        self._make_user(self.db_a, nfc_token="tok-conc-success")
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)

        due_a = collect_due_early_reminders(self.db_a, trigger_at)
        _due_user, alert, claim_at = due_a[0]
        self.assertTrue(mark_alert_notified(self.db_a, alert.id, trigger_at, claim_at))

        due_b = collect_due_early_reminders(self.db_b, trigger_at + timedelta(hours=1))
        self.assertEqual(due_b, [])

    def test_sos_success_starts_escalation_cooldown_across_sessions(self):
        user = self._make_user(self.db_a, nfc_token="tok-conc-sos-cooldown")
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db_a.add(emergency)
        self.db_a.commit()
        self.db_a.refresh(emergency)

        now = datetime.now(timezone.utc)
        due_a = collect_due_sos_notifications(self.db_a, now)
        self.assertEqual(len(due_a), 1)
        _due_user, due_emergency, claim_at = due_a[0]
        self.assertTrue(mark_sos_notified(self.db_a, due_emergency.id, now, claim_at))

        soon = now + timedelta(seconds=SOS_RETRY_INTERVAL_SECONDS - 5)
        self.assertEqual(collect_due_sos_notifications(self.db_b, soon), [])

        later = now + timedelta(seconds=SOS_RETRY_INTERVAL_SECONDS + 5)
        due_b = collect_due_sos_notifications(self.db_b, later)
        self.assertEqual(len(due_b), 1)

    def test_non_open_sos_cannot_be_marked_successful_across_sessions(self):
        # Phase S7 locked 'resolved' (not 'acknowledged') as the status that
        # stops escalation/marking -- an admin acknowledging concurrently
        # must NOT block this send from being recorded successful (see
        # tests/test_safety_sos_lifecycle_s7.py). Updated to use the actual
        # S7 admin action ('resolved') that fails this closed instead.
        user = self._make_user(self.db_a, nfc_token="tok-conc-sos-nonopen")
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db_a.add(emergency)
        self.db_a.commit()
        self.db_a.refresh(emergency)

        due_a = collect_due_sos_notifications(self.db_a, datetime.now(timezone.utc))
        self.assertEqual(len(due_a), 1)
        _due_user, due_emergency, claim_at = due_a[0]

        # Session B (the S7 admin resolve route) resolves the SOS while
        # session A still holds the delivery lease.
        emergency_b = (
            self.db_b.query(models.SafetyEmergency)
            .filter(models.SafetyEmergency.id == emergency.id)
            .first()
        )
        emergency_b.status = "resolved"
        self.db_b.commit()

        # Session A's send "succeeds", and it still holds the exact claim
        # it won, but marking must fail closed because the row is no
        # longer open/acknowledged by the time it tries to record success.
        marked = mark_sos_notified(self.db_a, due_emergency.id, datetime.now(timezone.utc), claim_at)
        self.assertFalse(marked)

    # ── lease-ownership correction: stale worker cannot act on a reclaimed
    # lease ───────────────────────────────────────────────────────────────

    def test_stale_alert_owner_cannot_release_or_mark_after_reclaim(self):
        """A claims -> lease expires -> B reclaims with a different
        claimed_at -> A's release/mark (using A's stale claim_at) must
        fail and B's lease must remain -> B's own release succeeds."""
        self._make_user(self.db_a, nfc_token="tok-conc-stale-alert")
        trigger_at = datetime(2026, 8, 19, 20, 30, tzinfo=timezone.utc)

        due_a = collect_due_early_reminders(self.db_a, trigger_at)
        self.assertEqual(len(due_a), 1)
        _user_a, alert_a, claim_a = due_a[0]

        expired = trigger_at + timedelta(seconds=DELIVERY_LEASE_SECONDS + 5)
        due_b = collect_due_early_reminders(self.db_b, expired)
        self.assertEqual(len(due_b), 1)
        _user_b, alert_b, claim_b = due_b[0]
        self.assertEqual(alert_a.id, alert_b.id)
        self.assertNotEqual(claim_a, claim_b)

        # Stale A's release, using its now-superseded claim, must fail and
        # leave B's lease untouched.
        self.assertFalse(release_alert_delivery_claim(self.db_a, alert_a.id, claim_a))

        # Stale A's success mark, using the same superseded claim, must
        # also fail -- B's lease must still be intact afterward.
        self.assertFalse(mark_alert_notified(self.db_a, alert_a.id, expired, claim_a))

        still_leased_by_b = (
            self.db_b.query(models.SafetyAlert).filter(models.SafetyAlert.id == alert_b.id).first()
        )
        self.assertEqual(still_leased_by_b.delivery_claimed_at, claim_b)
        self.assertIsNone(still_leased_by_b.notified_at)

        # B, the genuine current owner, can release using its own claim.
        self.assertTrue(release_alert_delivery_claim(self.db_b, alert_b.id, claim_b))

    def test_stale_sos_owner_cannot_release_or_mark_after_reclaim(self):
        """Same scenario as the alert case, for SOS: A claims -> lease
        expires -> B reclaims with a different claimed_at -> A's
        release/mark (using A's stale claim_at) must fail and B's lease
        must remain -> B's own mark succeeds."""
        user = self._make_user(self.db_a, nfc_token="tok-conc-stale-sos")
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db_a.add(emergency)
        self.db_a.commit()

        now = datetime.now(timezone.utc)
        due_a = collect_due_sos_notifications(self.db_a, now)
        self.assertEqual(len(due_a), 1)
        _user_a, emergency_a, claim_a = due_a[0]

        expired = now + timedelta(seconds=DELIVERY_LEASE_SECONDS + 5)
        due_b = collect_due_sos_notifications(self.db_b, expired)
        self.assertEqual(len(due_b), 1)
        _user_b, emergency_b, claim_b = due_b[0]
        self.assertEqual(emergency_a.id, emergency_b.id)
        self.assertNotEqual(claim_a, claim_b)

        # Stale A's release, using its now-superseded claim, must fail and
        # leave B's lease untouched.
        self.assertFalse(release_sos_delivery_claim(self.db_a, emergency_a.id, claim_a))

        # Stale A's success mark, using the same superseded claim, must
        # also fail -- B's lease must still be intact afterward.
        self.assertFalse(mark_sos_notified(self.db_a, emergency_a.id, expired, claim_a))

        still_leased_by_b = (
            self.db_b.query(models.SafetyEmergency)
            .filter(models.SafetyEmergency.id == emergency_b.id)
            .first()
        )
        self.assertEqual(still_leased_by_b.notification_claimed_at, claim_b)
        self.assertIsNone(still_leased_by_b.last_notified_at)

        # B, the genuine current owner, can mark success using its own
        # claim.
        self.assertTrue(mark_sos_notified(self.db_b, emergency_b.id, expired, claim_b))


if __name__ == "__main__":
    unittest.main()
