"""Regression tests for Safety Engine v1 Phase S5 (Daily Safety State /
Deadline Engine — safety_deadline.py + SafetyDailyState).

Mirrors the S1/S4 test harness: an isolated in-memory SQLite database, no
import of main.py. Uses safety_deadline.py functions directly (with an
explicit now_utc) plus safety_public.submit_check_in for the check-in
integration path.
"""
import os
import sys
import unittest
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import models
from database import Base
from safety_deadline import (
    _first_eligible_safety_date,
    evaluate_all_active_users,
    evaluate_user_deadline,
    get_or_create_daily_state,
    local_deadline_utc,
    local_safety_date,
    resolve_checkin,
)
from safety_public import submit_check_in, SafetyGPSPayload


class SafetyDeadlineEngineS5Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _make_user(self, nfc_token="tok-1", timezone_name="America/New_York",
                    deadline=time(21, 0), is_active=True, created_at=None):
        kwargs = {}
        if created_at is not None:
            kwargs["created_at"] = created_at
        user = models.SafetyUser(
            display_name="Alice",
            timezone=timezone_name,
            daily_deadline=deadline,
            early_reminder_minutes=30,
            nfc_token=nfc_token,
            is_active=is_active,
            **kwargs,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def _day_row(self, user, d):
        return (
            self.db.query(models.SafetyDailyState)
            .filter(
                models.SafetyDailyState.user_id == user.id,
                models.SafetyDailyState.safety_date == d,
            )
            .one()
        )

    # ── timezone-aware safety-day / deadline calculation ────────────────

    def test_local_safety_date_uses_user_timezone_not_utc_date(self):
        user = self._make_user(timezone_name="Pacific/Auckland")  # UTC+12/+13
        at_utc = datetime(2026, 8, 19, 20, 0, tzinfo=timezone.utc)  # next day in Auckland
        result = local_safety_date(user, at_utc)
        expected = at_utc.astimezone(ZoneInfo("Pacific/Auckland")).date()
        self.assertEqual(result, expected)
        self.assertNotEqual(result, at_utc.date())

    def test_local_deadline_utc_converts_correctly(self):
        user = self._make_user(timezone_name="America/New_York", deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline = local_deadline_utc(user, d)
        # America/New_York is UTC-4 in August (EDT) -> 21:00 local = 01:00 UTC next day
        self.assertEqual(deadline, datetime(2026, 8, 20, 1, 0, tzinfo=timezone.utc))

    def test_local_deadline_utc_respects_dst_difference(self):
        user = self._make_user(timezone_name="America/New_York", deadline=time(21, 0))
        summer = local_deadline_utc(user, date(2026, 7, 1))   # EDT, UTC-4
        winter = local_deadline_utc(user, date(2026, 1, 1))   # EST, UTC-5
        self.assertEqual(summer.hour, 1)   # 21:00 EDT -> 01:00 UTC
        self.assertEqual(winter.hour, 2)   # 21:00 EST -> 02:00 UTC

    def test_does_not_hardcode_a_specific_timezone(self):
        user = self._make_user(timezone_name="Asia/Phnom_Penh", deadline=time(21, 0))
        deadline = local_deadline_utc(user, date(2026, 8, 19))
        # Asia/Phnom_Penh is UTC+7 year-round -> 21:00 local = 14:00 UTC same day
        self.assertEqual(deadline, datetime(2026, 8, 19, 14, 0, tzinfo=timezone.utc))

    def test_dst_spring_forward_nonexistent_deadline_is_deterministic(self):
        # 2026-03-08: America/New_York clocks jump 02:00 -> 03:00. 02:30 that
        # day does not exist as a wall-clock instant.
        user = self._make_user(timezone_name="America/New_York", deadline=time(2, 30))
        d = date(2026, 3, 8)
        first = local_deadline_utc(user, d)
        second = local_deadline_utc(user, d)
        self.assertEqual(first, second)  # deterministic, not merely "doesn't crash"

    def test_dst_fall_back_ambiguous_deadline_is_deterministic(self):
        # 2026-11-01: America/New_York clocks fall back 02:00 -> 01:00. 01:30
        # that day occurs twice (ambiguous).
        user = self._make_user(timezone_name="America/New_York", deadline=time(1, 30))
        d = date(2026, 11, 1)
        first = local_deadline_utc(user, d)
        second = local_deadline_utc(user, d)
        self.assertEqual(first, second)

    # ── daily state integrity ────────────────────────────────────────────

    def test_get_or_create_is_idempotent_and_unique(self):
        user = self._make_user()
        d = date(2026, 8, 19)
        row1 = get_or_create_daily_state(self.db, user, d)
        row2 = get_or_create_daily_state(self.db, user, d)
        self.db.commit()
        self.assertEqual(row1.id, row2.id)
        count = (
            self.db.query(models.SafetyDailyState)
            .filter(models.SafetyDailyState.user_id == user.id)
            .count()
        )
        self.assertEqual(count, 1)

    def test_duplicate_daily_state_prevented_at_db_level(self):
        user = self._make_user()
        d = date(2026, 8, 19)
        row = models.SafetyDailyState(
            user_id=user.id,
            safety_date=d,
            status="pending",
            deadline_utc=local_deadline_utc(user, d),
        )
        self.db.add(row)
        self.db.commit()

        dupe = models.SafetyDailyState(
            user_id=user.id,
            safety_date=d,
            status="pending",
            deadline_utc=local_deadline_utc(user, d),
        )
        self.db.add(dupe)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_new_daily_state_starts_pending(self):
        user = self._make_user()
        row = get_or_create_daily_state(self.db, user, date(2026, 8, 19))
        self.db.commit()
        self.assertEqual(row.status, "pending")

    def test_repeated_recovery_creates_no_duplicate_rows(self):
        user = self._make_user(deadline=time(21, 0), created_at=datetime(2026, 8, 1, tzinfo=timezone.utc))
        now = datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc)
        evaluate_user_deadline(self.db, user, now_utc=now)
        first_count = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).count()
        evaluate_user_deadline(self.db, user, now_utc=now)
        second_count = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).count()
        self.assertEqual(first_count, second_count)

    # ── before deadline ──────────────────────────────────────────────────

    def test_before_deadline_remains_pending(self):
        user = self._make_user(deadline=time(21, 0))
        now = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)  # well before deadline
        row = evaluate_user_deadline(self.db, user, now_utc=now)
        self.assertEqual(row.status, "pending")

    # ── valid on-time check-in -> safe ──────────────────────────────────

    def test_ontime_checkin_marks_local_safety_day_safe(self):
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)
        checkin = models.SafetyCheckIn(
            user_id=user.id, latitude=1.0, longitude=2.0, source="public_web",
            checked_in_at=deadline_utc - timedelta(minutes=5),
        )
        self.db.add(checkin)
        self.db.flush()
        row = resolve_checkin(self.db, user, checkin)
        self.db.commit()
        self.assertEqual(row.status, "safe")
        self.assertEqual(row.checkin_id, checkin.id)

    def test_checkin_integration_via_submit_check_in_marks_safe(self):
        user = self._make_user()
        submit_check_in(
            user.secure_token,
            SafetyGPSPayload(latitude=1.0, longitude=2.0),
            self.db,
        )
        rows = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).all()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status, "safe")
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 1)

    def test_existing_s4_response_shape_unchanged(self):
        user = self._make_user()
        resp = submit_check_in(
            user.secure_token,
            SafetyGPSPayload(latitude=1.0, longitude=2.0),
            self.db,
        )
        self.assertEqual(resp.status, "ok")

    # ── atomicity: check-in + daily-state commit or fail together ───────

    def test_checkin_and_daily_state_are_atomic_on_failure(self):
        """If resolve_checkin raises before the caller commits, neither the
        SafetyCheckIn row nor any daily-state row should persist."""
        user = self._make_user()

        def _boom(db, user, checkin):
            raise RuntimeError("simulated S5 failure")

        import safety_public
        original = safety_public.resolve_checkin
        safety_public.resolve_checkin = _boom
        try:
            with self.assertRaises(RuntimeError):
                submit_check_in(
                    user.secure_token,
                    SafetyGPSPayload(latitude=1.0, longitude=2.0),
                    self.db,
                )
        finally:
            safety_public.resolve_checkin = original

        self.db.rollback()
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)
        self.assertEqual(self.db.query(models.SafetyDailyState).count(), 0)

    # ── evaluator must never overwrite SAFE with MISSED ─────────────────

    def test_evaluator_does_not_overwrite_existing_safe_state(self):
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)
        checkin = models.SafetyCheckIn(
            user_id=user.id, latitude=1.0, longitude=2.0, source="public_web",
            checked_in_at=deadline_utc - timedelta(minutes=1),
        )
        self.db.add(checkin)
        self.db.flush()
        resolve_checkin(self.db, user, checkin)
        self.db.commit()

        after_deadline = deadline_utc + timedelta(minutes=5)
        row = evaluate_user_deadline(self.db, user, now_utc=after_deadline)
        self.assertEqual(row.status, "safe")

    # ── MISSED is terminal in S5 — a late check-in never rewrites it ────

    def test_missed_day_is_not_rewritten_safe_by_late_checkin(self):
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)

        # No check-in before the deadline -> evaluator resolves MISSED.
        evaluate_user_deadline(self.db, user, now_utc=deadline_utc + timedelta(minutes=1))
        self.assertEqual(self._day_row(user, d).status, "missed")

        # A check-in submitted afterward (necessarily late, since the
        # deadline has already passed) must not flip it back to SAFE.
        late_checkin = models.SafetyCheckIn(
            user_id=user.id, latitude=1.0, longitude=2.0, source="public_web",
            checked_in_at=deadline_utc + timedelta(minutes=10),
        )
        self.db.add(late_checkin)
        self.db.flush()
        row = resolve_checkin(self.db, user, late_checkin)
        self.db.commit()
        self.assertEqual(row.status, "missed")
        self.assertEqual(self._day_row(user, d).status, "missed")

    def test_resolve_checkin_does_not_overwrite_concurrently_missed_row(self):
        """Simulates the stale-row race: the check-in transaction loads the
        daily-state row while it is still PENDING (and holds that stale
        in-memory copy); before resolve_checkin's own transition runs, a
        concurrent transaction (a different session -- standing in for the
        evaluator) independently commits PENDING -> MISSED. resolve_checkin
        must not blindly overwrite that with SAFE: its transition is a
        conditional UPDATE guarded by status='pending', so on the stale row
        it becomes a no-op, and the row is re-read afterward so the result
        reflects the real persisted MISSED state, not the stale guess."""
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)

        # Check-in transaction's own "read" of the row -- still PENDING.
        stale_row = get_or_create_daily_state(self.db, user, d)
        self.db.commit()
        self.assertEqual(stale_row.status, "pending")

        # A concurrent transaction (separate session/connection, standing in
        # for the evaluator) transitions PENDING -> MISSED independently.
        other_db = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)()
        try:
            updated = (
                other_db.query(models.SafetyDailyState)
                .filter(
                    models.SafetyDailyState.id == stale_row.id,
                    models.SafetyDailyState.status == "pending",
                )
                .update(
                    {"status": "missed", "evaluated_at": deadline_utc + timedelta(minutes=1)},
                    synchronize_session=False,
                )
            )
            self.assertEqual(updated, 1)
            other_db.commit()
        finally:
            other_db.close()

        # self.db's identity map still holds the stale PENDING copy --
        # exactly the race condition under test.
        self.assertEqual(stale_row.status, "pending")

        # An on-time check-in now arrives on the original (check-in) session.
        checkin = models.SafetyCheckIn(
            user_id=user.id, latitude=1.0, longitude=2.0, source="public_web",
            checked_in_at=deadline_utc - timedelta(minutes=1),
        )
        self.db.add(checkin)
        self.db.flush()
        row = resolve_checkin(self.db, user, checkin)
        self.db.commit()

        self.assertEqual(row.status, "missed")
        self.assertEqual(self._day_row(user, d).status, "missed")

    # ── evaluator reconciling an already-persisted qualifying check-in ──

    def test_evaluator_reconciling_persisted_qualifying_checkin_resolves_safe(self):
        """A qualifying (on-time) SafetyCheckIn already committed, but the
        daily-state row doesn't exist yet (e.g. multi-day backfill catching
        up) -- the evaluator must resolve that day to SAFE, not MISSED."""
        user = self._make_user(deadline=time(21, 0), created_at=datetime(2026, 8, 1, tzinfo=timezone.utc))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)

        checkin = models.SafetyCheckIn(
            user_id=user.id, latitude=1.0, longitude=2.0, source="public_web",
            checked_in_at=deadline_utc - timedelta(minutes=10),
        )
        self.db.add(checkin)
        self.db.commit()
        self.db.refresh(checkin)
        # No SafetyDailyState row exists yet for `d` at this point.

        evaluate_user_deadline(self.db, user, now_utc=deadline_utc + timedelta(minutes=5))
        row = self._day_row(user, d)
        self.assertEqual(row.status, "safe")
        self.assertEqual(row.checkin_id, checkin.id)

    # ── new user must not get fake pre-existence MISSED days ────────────

    def test_new_user_gets_no_historical_days_before_created_at(self):
        # User created well before that local day's deadline (21:00) --
        # that day itself is eligible.
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 19, 10, 0, tzinfo=timezone.utc),  # 06:00 EDT Aug 19
        )
        anchor = _first_eligible_safety_date(user)
        self.assertEqual(anchor, date(2026, 8, 19))

        evaluate_user_deadline(self.db, user, now_utc=datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc))
        rows = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).all()
        earliest = min(r.safety_date for r in rows)
        self.assertEqual(earliest, anchor)
        self.assertTrue(all(r.safety_date >= anchor for r in rows))

    # ── first eligible safety day boundary (created before/after deadline) ──

    def test_created_before_that_days_deadline_is_eligible_that_day(self):
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 20, 0, 0, tzinfo=timezone.utc),  # 20:00 EDT Aug 19
        )
        self.assertEqual(_first_eligible_safety_date(user), date(2026, 8, 19))

    def test_created_after_that_days_deadline_starts_next_day(self):
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 20, 2, 0, tzinfo=timezone.utc),  # 22:00 EDT Aug 19, past 21:00 deadline
        )
        self.assertEqual(_first_eligible_safety_date(user), date(2026, 8, 20))

    def test_created_exactly_at_deadline_starts_next_day(self):
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 20, 1, 0, tzinfo=timezone.utc),  # exactly 21:00 EDT Aug 19
        )
        self.assertEqual(_first_eligible_safety_date(user), date(2026, 8, 20))

    def test_created_after_deadline_produces_no_missed_row_for_creation_day(self):
        # Created at 22:00 EDT Aug 19 -- already past that day's 21:00
        # deadline. Aug 19 must never get a SafetyDailyState row at all
        # (not pending, and definitely not a fabricated MISSED).
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 20, 2, 0, tzinfo=timezone.utc),
        )
        # Evaluate well after Aug 20's deadline too, so both days' deadlines
        # have passed by the time evaluation runs.
        deadline_aug20 = local_deadline_utc(user, date(2026, 8, 20))
        evaluate_user_deadline(self.db, user, now_utc=deadline_aug20 + timedelta(minutes=5))

        aug19_row = (
            self.db.query(models.SafetyDailyState)
            .filter(
                models.SafetyDailyState.user_id == user.id,
                models.SafetyDailyState.safety_date == date(2026, 8, 19),
            )
            .first()
        )
        self.assertIsNone(aug19_row)
        self.assertEqual(self._day_row(user, date(2026, 8, 20)).status, "missed")

    # ── multi-day downtime recovery ─────────────────────────────────────

    def test_multi_day_downtime_recovery_catches_every_missed_day(self):
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        # App effectively "down" from before Aug 19 until Aug 22 — first
        # evaluation happens well after several deadlines have passed.
        now = datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc)
        evaluate_user_deadline(self.db, user, now_utc=now)

        for d in (date(2026, 8, 19), date(2026, 8, 20), date(2026, 8, 21)):
            self.assertEqual(self._day_row(user, d).status, "missed")
        self.assertEqual(self._day_row(user, date(2026, 8, 22)).status, "pending")

    def test_recovery_is_bounded_not_regenerating_full_history_each_tick(self):
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        now = datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc)
        evaluate_user_deadline(self.db, user, now_utc=now)
        count_after_first = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).count()

        # Re-run a short while later, same local day: should add at most 1 row.
        later = now + timedelta(minutes=5)
        evaluate_user_deadline(self.db, user, now_utc=later)
        count_after_second = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).count()
        self.assertLessEqual(count_after_second - count_after_first, 1)

    def test_missing_middle_day_between_two_existing_days_is_filled_and_resolved(self):
        """Aug 17 and Aug 19 already have SafetyDailyState rows; Aug 18 has
        none (e.g. from an anomaly/manual edit). MAX(safety_date) would be
        Aug 19, which would permanently skip repairing Aug 18 -- evaluation
        must detect and fill the internal gap instead."""
        user = self._make_user(
            deadline=time(21, 0),
            created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
        )
        deadline_17 = local_deadline_utc(user, date(2026, 8, 17))
        deadline_19 = local_deadline_utc(user, date(2026, 8, 19))

        self.db.add(models.SafetyDailyState(
            user_id=user.id, safety_date=date(2026, 8, 17), status="missed",
            deadline_utc=deadline_17, evaluated_at=deadline_17 + timedelta(minutes=1),
        ))
        self.db.add(models.SafetyDailyState(
            user_id=user.id, safety_date=date(2026, 8, 19), status="missed",
            deadline_utc=deadline_19, evaluated_at=deadline_19 + timedelta(minutes=1),
        ))
        self.db.commit()
        # Aug 18 deliberately has no row at all.
        self.assertIsNone(
            self.db.query(models.SafetyDailyState)
            .filter(
                models.SafetyDailyState.user_id == user.id,
                models.SafetyDailyState.safety_date == date(2026, 8, 18),
            )
            .first()
        )

        now = datetime(2026, 8, 22, 15, 0, tzinfo=timezone.utc)
        evaluate_user_deadline(self.db, user, now_utc=now)

        gap_row = self._day_row(user, date(2026, 8, 18))
        self.assertEqual(gap_row.status, "missed")  # its deadline had already passed, no check-in
        # The two pre-existing days are untouched, and every day from the
        # earliest existing row through today now has exactly one row.
        self.assertEqual(self._day_row(user, date(2026, 8, 17)).status, "missed")
        self.assertEqual(self._day_row(user, date(2026, 8, 19)).status, "missed")
        for d in (date(2026, 8, 17), date(2026, 8, 18), date(2026, 8, 19),
                  date(2026, 8, 20), date(2026, 8, 21)):
            self.assertEqual(self._day_row(user, d).status, "missed")
        self.assertEqual(self._day_row(user, date(2026, 8, 22)).status, "pending")

        rows = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).all()
        dates = [r.safety_date for r in rows]
        self.assertEqual(len(dates), len(set(dates)))  # no duplicate day rows
        count = len(rows)

        # Idempotent: re-running does not create a duplicate for the gap day.
        evaluate_user_deadline(self.db, user, now_utc=now)
        count_after_rerun = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == user.id
        ).count()
        self.assertEqual(count_after_rerun, count)

    # ── duplicate evaluator execution ───────────────────────────────────

    def test_duplicate_evaluator_execution_is_idempotent(self):
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)
        after_deadline = deadline_utc + timedelta(minutes=1)

        row1 = evaluate_user_deadline(self.db, user, now_utc=after_deadline)
        row2 = evaluate_user_deadline(self.db, user, now_utc=after_deadline)
        self.assertEqual(row1.id, row2.id)
        self.assertEqual(row1.status, "missed")
        self.assertEqual(row2.status, "missed")

    def test_evaluate_all_active_users_skips_inactive(self):
        active_user = self._make_user(nfc_token="tok-active", deadline=time(0, 0))
        inactive_user = self._make_user(nfc_token="tok-inactive", is_active=False, deadline=time(0, 0))
        now = datetime(2026, 8, 20, 5, 0, tzinfo=timezone.utc)  # well past midnight deadline
        evaluate_all_active_users(self.db, now_utc=now)

        active_rows = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == active_user.id
        ).count()
        inactive_rows = self.db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.user_id == inactive_user.id
        ).count()
        self.assertGreaterEqual(active_rows, 1)
        self.assertEqual(inactive_rows, 0)

    # ── check-in / deadline boundary behavior ───────────────────────────

    def test_exactly_at_deadline_counts_as_passed(self):
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)
        row = evaluate_user_deadline(self.db, user, now_utc=deadline_utc)
        self.assertEqual(row.status, "missed")

    def test_one_second_before_deadline_remains_pending(self):
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)
        just_before = deadline_utc - timedelta(seconds=1)
        row = evaluate_user_deadline(self.db, user, now_utc=just_before)
        self.assertEqual(row.status, "pending")

    def test_checkin_exactly_at_deadline_does_not_qualify(self):
        user = self._make_user(deadline=time(21, 0))
        d = date(2026, 8, 19)
        deadline_utc = local_deadline_utc(user, d)
        checkin = models.SafetyCheckIn(
            user_id=user.id, latitude=1.0, longitude=2.0, source="public_web",
            checked_in_at=deadline_utc,
        )
        self.db.add(checkin)
        self.db.flush()
        row = resolve_checkin(self.db, user, checkin)
        self.db.commit()
        self.assertEqual(row.status, "pending")


if __name__ == "__main__":
    unittest.main()
