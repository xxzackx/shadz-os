"""Regression tests for Safety Engine v1 Phase S7 — SOS acknowledge /
resolution lifecycle (safety_notify.acknowledge_sos / resolve_sos, and the
escalation-eligibility change to collect_due_sos_notifications /
_claim_sos_delivery / mark_sos_notified).

Locked S7 lifecycle: active (open) -> acknowledged -> resolved, STRICTLY --
direct open -> resolved is not a valid transition.
  - acknowledge: open -> acknowledged only; repeat/late calls are safe no-ops
    (never regresses a resolved SOS back to acknowledged).
  - resolve: acknowledged -> resolved ONLY; a still-open emergency is left
    completely untouched by resolve_sos (the admin route layer, tested in
    test_safety_admin_sos_endpoints_s7.py, rejects that case with 409); a
    repeat resolve call on an already-resolved emergency is a safe no-op.
  - SOS escalation (collect_due_sos_notifications) stays eligible for BOTH
    'open' and 'acknowledged' -- acknowledging alone must not stop
    escalation, only resolving does. This is the one behavioral change to
    the existing S6 escalation-eligibility query.

Follows the S6 test harness: an isolated in-memory SQLite database, no
import of main.py, no real Telegram calls (this file never calls
safety_telegram at all -- it only exercises the DB-level claim/resolve
functions in safety_notify.py, which is exactly what
collect_due_sos_notifications/acknowledge_sos/resolve_sos are).
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
from safety_notify import (
    SOS_RETRY_INTERVAL_SECONDS,
    acknowledge_sos,
    collect_due_sos_notifications,
    mark_sos_notified,
    resolve_sos,
)


class SafetySOSLifecycleS7Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _make_user(self, nfc_token="tok-1"):
        user = models.SafetyUser(
            display_name="Alice",
            timezone="UTC",
            daily_deadline=time(21, 0),
            early_reminder_minutes=30,
            nfc_token=nfc_token,
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def _make_sos(self, user, status="open"):
        emergency = models.SafetyEmergency(user_id=user.id, status=status)
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)
        return emergency

    # ── SOS starts active ────────────────────────────────────────────

    def test_sos_starts_open(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        self.assertEqual(emergency.status, "open")
        self.assertIsNone(emergency.acknowledged_at)
        self.assertIsNone(emergency.resolved_at)

    # ── acknowledge ──────────────────────────────────────────────────

    def test_admin_acknowledge_transitions_to_acknowledged_not_resolved(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        now = datetime.now(timezone.utc)

        updated = acknowledge_sos(self.db, emergency.id, now)

        self.assertEqual(updated.status, "acknowledged")
        self.assertIsNotNone(updated.acknowledged_at)
        self.assertIsNone(updated.resolved_at)

    def test_repeated_acknowledge_is_safe_and_idempotent(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        first = acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))
        first_ack_at = first.acknowledged_at

        second = acknowledge_sos(
            self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=5)
        )

        self.assertEqual(second.status, "acknowledged")
        self.assertEqual(second.acknowledged_at, first_ack_at)

    def test_acknowledge_after_resolve_does_not_regress_status(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))
        resolve_sos(self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=5))

        updated = acknowledge_sos(
            self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=10)
        )

        self.assertEqual(updated.status, "resolved")
        self.assertIsNotNone(updated.acknowledged_at)

    def test_acknowledge_unknown_emergency_returns_none(self):
        self.assertIsNone(acknowledge_sos(self.db, 999999, datetime.now(timezone.utc)))

    # ── resolve ──────────────────────────────────────────────────────

    def test_admin_resolve_transitions_acknowledged_to_resolved(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))
        now = datetime.now(timezone.utc) + timedelta(seconds=5)

        updated = resolve_sos(self.db, emergency.id, now)

        self.assertEqual(updated.status, "resolved")
        self.assertIsNotNone(updated.resolved_at)

    def test_resolve_on_open_sos_is_rejected_and_leaves_it_open(self):
        # Locked S7 lifecycle: open -> resolved directly is not a valid
        # transition. resolve_sos leaves a still-open emergency completely
        # untouched -- the admin route layer (safety_admin.py, tested in
        # test_safety_admin_sos_endpoints_s7.py) is what turns this into an
        # HTTP 409; at the state-machine level here, the guarantee is simply
        # that nothing changes.
        user = self._make_user()
        emergency = self._make_sos(user)

        updated = resolve_sos(self.db, emergency.id, datetime.now(timezone.utc))

        self.assertEqual(updated.status, "open")
        self.assertIsNone(updated.resolved_at)
        self.assertIsNone(updated.acknowledged_at)

    def test_resolve_from_acknowledged_also_works(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))

        updated = resolve_sos(
            self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=5)
        )

        self.assertEqual(updated.status, "resolved")
        self.assertIsNotNone(updated.acknowledged_at)
        self.assertIsNotNone(updated.resolved_at)

    def test_repeated_resolve_is_safe_and_idempotent(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))
        first = resolve_sos(self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=5))
        first_resolved_at = first.resolved_at

        second = resolve_sos(
            self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=10)
        )

        self.assertEqual(second.status, "resolved")
        self.assertEqual(second.resolved_at, first_resolved_at)

    def test_resolve_unknown_emergency_returns_none(self):
        self.assertIsNone(resolve_sos(self.db, 999999, datetime.now(timezone.utc)))

    # ── escalation continues through acknowledged, stops at resolved ───

    def test_escalation_continues_after_acknowledge(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))

        due = collect_due_sos_notifications(self.db, datetime.now(timezone.utc))

        self.assertEqual(len(due), 1)
        due_user, due_emergency, claim_at = due[0]
        self.assertEqual(due_emergency.id, emergency.id)
        self.assertEqual(due_emergency.status, "acknowledged")

    def test_escalation_retry_cadence_still_applies_while_acknowledged(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))

        now = datetime.now(timezone.utc)
        due_first = collect_due_sos_notifications(self.db, now)
        self.assertEqual(len(due_first), 1)
        _, _, claim_at = due_first[0]
        mark_sos_notified(self.db, emergency.id, now, claim_at)

        # Immediately after a successful send, still within the retry
        # cooldown -- not due again yet, exactly like the pre-S7 'open'
        # behavior.
        due_immediately_after = collect_due_sos_notifications(self.db, now)
        self.assertEqual(due_immediately_after, [])

        later = now + timedelta(seconds=SOS_RETRY_INTERVAL_SECONDS + 1)
        due_after_cooldown = collect_due_sos_notifications(self.db, later)
        self.assertEqual(len(due_after_cooldown), 1)
        self.assertEqual(due_after_cooldown[0][1].status, "acknowledged")

    def test_escalation_stops_once_resolved(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))
        resolve_sos(self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=5))

        due = collect_due_sos_notifications(
            self.db, datetime.now(timezone.utc) + timedelta(seconds=10)
        )

        self.assertEqual(due, [])

    def test_escalation_stops_once_resolved_even_after_prior_acknowledge(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))
        resolve_sos(
            self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=5)
        )

        due = collect_due_sos_notifications(
            self.db, datetime.now(timezone.utc) + timedelta(seconds=10)
        )

        self.assertEqual(due, [])

    # ── acknowledgement never erases the SOS or fabricates "safe" ──────

    def test_acknowledge_does_not_mark_daily_state_or_touch_other_tables(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))

        self.assertEqual(self.db.query(models.SafetyDailyState).count(), 0)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)
        # The emergency row itself is never deleted by acknowledge/resolve.
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 1)

    def test_resolved_sos_remains_auditable_not_deleted(self):
        user = self._make_user()
        emergency = self._make_sos(user)
        acknowledge_sos(self.db, emergency.id, datetime.now(timezone.utc))
        resolve_sos(
            self.db, emergency.id, datetime.now(timezone.utc) + timedelta(seconds=5)
        )

        row = self.db.query(models.SafetyEmergency).filter_by(id=emergency.id).one()
        self.assertEqual(row.status, "resolved")
        self.assertIsNotNone(row.acknowledged_at)
        self.assertIsNotNone(row.resolved_at)


if __name__ == "__main__":
    unittest.main()
