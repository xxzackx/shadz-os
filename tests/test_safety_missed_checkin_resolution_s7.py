"""Regression tests for Safety Engine v1 Phase S7 — late/missed check-in
resolution (safety_notify.resolve_missed_checkin_alert, wired into
safety_public.submit_check_in).

Scope: a SafetyDailyState that has already resolved to 'missed' (S5's
terminal-MISSED rule for the *daily state* is unchanged and NOT touched by
these tests) can still have its associated missed_checkin SafetyAlert
resolved once the same user submits a later ("late") check-in for that exact
day — persisted via SafetyAlert.status/resolved_at/resolved_checkin_id
(present on the model since Phase S6, unused until now), not a parallel
alert system.

Follows the S6 test harness: an isolated in-memory SQLite database, no
import of main.py. Daily-state/alert rows are constructed directly (rather
than driven through the real deadline evaluator, which depends on wall-clock
"now") so each test's "already missed" starting state is deterministic and
independent of when the suite happens to run.
"""
import os
import sys
import unittest
from datetime import datetime, time, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import models
from database import Base
from safety_notify import collect_due_missed_alerts, resolve_missed_checkin_alert
from safety_public import SafetyGPSPayload, submit_check_in


class SafetyMissedCheckinResolutionS7Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()
        # Anchored to real wall-clock "now" (rather than a fixed date) so
        # the one test below that drives the real submit_check_in entry
        # point (whose checked_in_at is always server-set to real now())
        # reliably lands on the same local safety day, safely after this
        # deadline.
        now = datetime.now(timezone.utc)
        self.today = now.date()
        self.deadline_utc = datetime.combine(self.today, time(0, 1), tzinfo=timezone.utc)

    def tearDown(self):
        self.db.close()

    def _make_user(self, nfc_token="tok-1", deadline=time(21, 0), is_active=True):
        user = models.SafetyUser(
            display_name="Alice",
            timezone="UTC",
            daily_deadline=deadline,
            early_reminder_minutes=30,
            nfc_token=nfc_token,
            is_active=is_active,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def _make_missed_daily_state(self, user, safety_date=None, deadline_utc=None):
        row = models.SafetyDailyState(
            user_id=user.id,
            safety_date=safety_date or self.today,
            status="missed",
            deadline_utc=deadline_utc or self.deadline_utc,
            evaluated_at=(deadline_utc or self.deadline_utc) + timedelta(seconds=1),
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def _make_missed_alert(self, user, safety_date=None, notified=False):
        alert = models.SafetyAlert(
            user_id=user.id,
            safety_date=safety_date or self.today,
            alert_type="missed_checkin",
            status="open",
            notified_at=self.deadline_utc + timedelta(minutes=1) if notified else None,
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        return alert

    def _late_checkin(self, user, checked_in_at=None):
        """A check-in guaranteed to land at/after self.deadline_utc, on the
        same daily-state row the tests already set up."""
        checkin = models.SafetyCheckIn(
            user_id=user.id,
            checked_in_at=checked_in_at or (self.deadline_utc + timedelta(minutes=5)),
            source="public_web",
        )
        self.db.add(checkin)
        self.db.commit()
        self.db.refresh(checkin)
        return checkin

    def _submit_late_checkin_via_public_route(self, user):
        """Drives the real safety_public.submit_check_in entry point --
        checked_in_at is server-set to real wall-clock now(), so callers
        must ensure self.deadline_utc is safely in the past relative to
        whenever this test actually runs."""
        payload = SafetyGPSPayload(latitude=1.0, longitude=2.0)
        return submit_check_in(user.secure_token, payload, self.db)

    # ── missed incident exists / later valid check-in resolves it ──────

    def test_missed_incident_exists_and_is_unresolved_initially(self):
        user = self._make_user()
        self._make_missed_daily_state(user)
        alert = self._make_missed_alert(user, notified=True)
        self.assertEqual(alert.status, "open")
        self.assertIsNone(alert.resolved_at)

    def test_later_valid_checkin_resolves_outstanding_missed_alert(self):
        user = self._make_user()
        self._make_missed_daily_state(user)
        alert = self._make_missed_alert(user, notified=True)

        # Exercises the actual public submit_check_in path end to end --
        # self.deadline_utc (00:01 UTC today, see setUp) is safely in the
        # past relative to real "now".
        resp = self._submit_late_checkin_via_public_route(user)
        self.assertEqual(resp.status, "ok")

        self.db.refresh(alert)
        self.assertEqual(alert.status, "resolved")

    def test_resolution_sets_correct_status_timestamp_and_checkin(self):
        user = self._make_user()
        self._make_missed_daily_state(user)

        checkin = self._late_checkin(user)
        alert = resolve_missed_checkin_alert(self.db, user.id, self.today, checkin.id)
        self.db.commit()

        self.assertEqual(alert.status, "resolved")
        self.assertIsNotNone(alert.resolved_at)
        self.assertEqual(alert.resolved_checkin_id, checkin.id)

    def test_resolves_pre_emptively_when_no_alert_row_exists_yet(self):
        """Covers the race where a late check-in arrives before the
        evaluator has created the missed_checkin SafetyAlert at all -- the
        alert is created already resolved, so it can never later be sent."""
        user = self._make_user()
        self._make_missed_daily_state(user)
        self.assertEqual(self.db.query(models.SafetyAlert).count(), 0)

        checkin = self._late_checkin(user)
        alert = resolve_missed_checkin_alert(self.db, user.id, self.today, checkin.id)
        self.db.commit()

        self.assertEqual(alert.status, "resolved")
        self.assertEqual(alert.resolved_checkin_id, checkin.id)
        self.assertEqual(self.db.query(models.SafetyAlert).count(), 1)

    # ── repeated processing is idempotent ───────────────────────────────

    def test_repeated_resolution_is_idempotent(self):
        user = self._make_user()
        self._make_missed_daily_state(user)
        alert = self._make_missed_alert(user, notified=True)

        checkin1 = self._late_checkin(user, self.deadline_utc + timedelta(minutes=5))
        resolve_missed_checkin_alert(self.db, user.id, self.today, checkin1.id)
        self.db.commit()
        self.db.refresh(alert)
        first_resolved_at = alert.resolved_at
        self.assertEqual(alert.resolved_checkin_id, checkin1.id)

        checkin2 = self._late_checkin(user, self.deadline_utc + timedelta(minutes=10))
        resolve_missed_checkin_alert(self.db, user.id, self.today, checkin2.id)
        self.db.commit()
        self.db.refresh(alert)

        # A second late check-in the same day must never re-resolve or
        # overwrite the first resolution.
        self.assertEqual(alert.status, "resolved")
        self.assertEqual(alert.resolved_at, first_resolved_at)
        self.assertEqual(alert.resolved_checkin_id, checkin1.id)

    def test_scheduler_never_recollects_a_resolved_missed_alert(self):
        user = self._make_user()
        self._make_missed_daily_state(user)
        checkin = self._late_checkin(user)
        resolve_missed_checkin_alert(self.db, user.id, self.today, checkin.id)
        self.db.commit()

        due = collect_due_missed_alerts(self.db, datetime.now(timezone.utc))
        self.assertEqual(due, [])

    def test_scheduler_still_collects_a_genuinely_unresolved_missed_alert(self):
        user = self._make_user()
        self._make_missed_daily_state(user)

        due = collect_due_missed_alerts(self.db, datetime.now(timezone.utc))
        self.assertEqual(len(due), 1)
        due_user, row, alert, claim_at = due[0]
        self.assertEqual(due_user.id, user.id)
        self.assertEqual(alert.status, "open")

    # ── next daily cycle still works ────────────────────────────────────

    def test_next_days_missed_alert_is_independent_of_a_prior_resolved_day(self):
        user = self._make_user()
        self._make_missed_daily_state(user, safety_date=self.today)
        checkin = self._late_checkin(user)
        resolve_missed_checkin_alert(self.db, user.id, self.today, checkin.id)
        self.db.commit()

        tomorrow = self.today + timedelta(days=1)
        self._make_missed_daily_state(
            user, safety_date=tomorrow, deadline_utc=self.deadline_utc + timedelta(days=1)
        )

        due = collect_due_missed_alerts(self.db, datetime.now(timezone.utc))
        self.assertEqual(len(due), 1)
        due_user, row, alert, claim_at = due[0]
        self.assertEqual(row.safety_date, tomorrow)
        self.assertEqual(alert.status, "open")

    # ── cross-user isolation ────────────────────────────────────────────

    def test_one_users_checkin_cannot_resolve_another_users_incident(self):
        user_a = self._make_user(nfc_token="tok-a")
        user_b = self._make_user(nfc_token="tok-b")
        self._make_missed_daily_state(user_a)
        self._make_missed_daily_state(user_b)
        alert_a = self._make_missed_alert(user_a, notified=True)
        alert_b = self._make_missed_alert(user_b, notified=True)

        checkin_a = self._late_checkin(user_a)
        resolve_missed_checkin_alert(self.db, user_a.id, self.today, checkin_a.id)
        self.db.commit()

        self.db.refresh(alert_a)
        self.db.refresh(alert_b)
        self.assertEqual(alert_a.status, "resolved")
        self.assertEqual(alert_b.status, "open")
        self.assertIsNone(alert_b.resolved_at)

    # ── safety invariant: a normal check-in never touches SOS ──────────

    def test_normal_checkin_never_resolves_an_unrelated_sos(self):
        user = self._make_user()
        self._make_missed_daily_state(user)
        emergency = models.SafetyEmergency(user_id=user.id, status="open")
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)

        self._submit_late_checkin_via_public_route(user)

        self.db.refresh(emergency)
        self.assertEqual(emergency.status, "open")
        self.assertIsNone(emergency.acknowledged_at)
        self.assertIsNone(emergency.resolved_at)


if __name__ == "__main__":
    unittest.main()
