"""Regression tests for SHADZ Safety Engine v1 Phase S8 same-day
daily_deadline usability (safety_admin.py — PATCH /admin/safety/users/{id}).

Prior S8 behavior: SafetyDailyState.deadline_utc is computed once and
persisted only when a daily state row is *created* (safety_deadline.
get_or_create_daily_state -> local_deadline_utc). Changing SafetyUser.
daily_deadline through the admin PATCH therefore had no effect on any
already-existing row until the next local safety day -- including today's
own still-open 'pending' row, making a same-day deadline correction
invisible to Admin until tomorrow.

Fix under test: when a PATCH actually changes daily_deadline AND today's
row (this user's own local safety date, via local_safety_date) exists and
is still 'pending', that one row's deadline_utc is recalculated in place
using the existing local_deadline_utc helper -- reusing exactly the
computation get_or_create_daily_state itself uses, not a re-implementation.
No new row is ever created here, the row's id never changes, and status is
never touched by this route (a recalculated deadline that has already
passed simply leaves the row 'pending' -- the normal evaluator transitions
it to 'missed' on its own next tick, unchanged).

Follows test_admin_safety_config_semantics_s8.py's existing convention:
runs against the real main.app + admin_router + verify_admin wiring (HTTP
Basic Auth) in a subprocess, with DATABASE_URL pointed at a throwaway temp
SQLite file so no test touches the real shadz.db or main.py's module-level
engine/Session state.

'now' is captured once from the real clock at the top of the script and
every expected value is derived from that captured instant -- never a
hardcoded calendar-date literal -- so this suite cannot become a wall-clock
time bomb the way tests/test_safety_notify_s6.py's
test_s5_evaluator_unaffected_by_s6_module did (that pre-existing, unrelated
flake is explicitly left alone here per scope).
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ADMIN_USER = "test-admin-s8-same-day"
_ADMIN_PASS = "test-pass-s8-same-day"

_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys
    from datetime import datetime, timedelta, timezone

    sys.path.insert(0, {REPO_ROOT!r})

    import main
    import models
    from database import SessionLocal
    from fastapi.testclient import TestClient
    from safety_deadline import get_or_create_daily_state, local_deadline_utc, local_safety_date

    result = {{}}
    client = TestClient(main.app)
    auth = ({_ADMIN_USER!r}, {_ADMIN_PASS!r})

    now = datetime.now(timezone.utc)
    # Comfortably future/past time-of-day offsets from the real captured
    # 'now', in UTC (the users below all use timezone="UTC"), so the
    # future/past relationship to 'now' holds regardless of when this
    # suite actually runs.
    future_deadline = (now + timedelta(hours=1)).time()
    past_deadline = (now - timedelta(hours=1)).time()
    initial_deadline = (now + timedelta(hours=2)).time()

    def make_user(db, nfc_token, deadline):
        user = models.SafetyUser(
            display_name="Same-Day User", timezone="UTC", daily_deadline=deadline,
            early_reminder_minutes=30, nfc_token=nfc_token, is_active=True,
            created_at=now - timedelta(days=3),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id

    # ── (1) today's pending row -> deadline_utc updates in place ────────
    db = SessionLocal()
    user1_id = make_user(db, "tok-same-day-1", initial_deadline)
    user1 = db.query(models.SafetyUser).filter(models.SafetyUser.id == user1_id).first()
    today1 = local_safety_date(user1, now)
    row1 = get_or_create_daily_state(db, user1, today1)
    db.commit()
    db.refresh(row1)
    row1_id = row1.id
    result["s1_deadline_before"] = row1.deadline_utc.isoformat()
    db.close()

    r = client.patch(
        f"/admin/safety/users/{{user1_id}}",
        json={{"daily_deadline": future_deadline.strftime("%H:%M:%S")}},
        auth=auth,
    )
    result["s1_patch_status"] = r.status_code

    verify = SessionLocal()
    reloaded_user1 = verify.query(models.SafetyUser).filter(models.SafetyUser.id == user1_id).first()
    reloaded_row1 = verify.query(models.SafetyDailyState).filter(models.SafetyDailyState.id == row1_id).first()
    result["s1_row_id_unchanged"] = (reloaded_row1.id == row1_id)
    result["s1_status_after"] = reloaded_row1.status
    result["s1_deadline_after"] = reloaded_row1.deadline_utc.isoformat()
    result["s1_expected_deadline"] = local_deadline_utc(reloaded_user1, today1).replace(tzinfo=None).isoformat()
    verify.close()

    # ── (2) today's safe row -> untouched ────────────────────────────────
    db = SessionLocal()
    user2_id = make_user(db, "tok-same-day-2", initial_deadline)
    user2 = db.query(models.SafetyUser).filter(models.SafetyUser.id == user2_id).first()
    today2 = local_safety_date(user2, now)
    row2 = get_or_create_daily_state(db, user2, today2)
    row2.status = "safe"
    db.commit()
    db.refresh(row2)
    row2_id = row2.id
    result["s2_deadline_before"] = row2.deadline_utc.isoformat()
    db.close()

    r = client.patch(
        f"/admin/safety/users/{{user2_id}}",
        json={{"daily_deadline": future_deadline.strftime("%H:%M:%S")}},
        auth=auth,
    )
    result["s2_patch_status"] = r.status_code

    verify = SessionLocal()
    reloaded_row2 = verify.query(models.SafetyDailyState).filter(models.SafetyDailyState.id == row2_id).first()
    result["s2_status_after"] = reloaded_row2.status
    result["s2_deadline_after"] = reloaded_row2.deadline_utc.isoformat()
    verify.close()

    # ── (3) today's missed row -> untouched ──────────────────────────────
    db = SessionLocal()
    user3_id = make_user(db, "tok-same-day-3", initial_deadline)
    user3 = db.query(models.SafetyUser).filter(models.SafetyUser.id == user3_id).first()
    today3 = local_safety_date(user3, now)
    row3 = get_or_create_daily_state(db, user3, today3)
    row3.status = "missed"
    db.commit()
    db.refresh(row3)
    row3_id = row3.id
    result["s3_deadline_before"] = row3.deadline_utc.isoformat()
    db.close()

    r = client.patch(
        f"/admin/safety/users/{{user3_id}}",
        json={{"daily_deadline": future_deadline.strftime("%H:%M:%S")}},
        auth=auth,
    )
    result["s3_patch_status"] = r.status_code

    verify = SessionLocal()
    reloaded_row3 = verify.query(models.SafetyDailyState).filter(models.SafetyDailyState.id == row3_id).first()
    result["s3_status_after"] = reloaded_row3.status
    result["s3_deadline_after"] = reloaded_row3.deadline_utc.isoformat()
    verify.close()

    # ── (4) a PAST day's pending row -> untouched (only today qualifies) ──
    db = SessionLocal()
    user4_id = make_user(db, "tok-same-day-4", initial_deadline)
    user4 = db.query(models.SafetyUser).filter(models.SafetyUser.id == user4_id).first()
    today4 = local_safety_date(user4, now)
    yesterday4 = today4 - timedelta(days=1)
    row4 = get_or_create_daily_state(db, user4, yesterday4)
    db.commit()
    db.refresh(row4)
    row4_id = row4.id
    result["s4_deadline_before"] = row4.deadline_utc.isoformat()
    result["s4_status_before"] = row4.status
    db.close()

    r = client.patch(
        f"/admin/safety/users/{{user4_id}}",
        json={{"daily_deadline": future_deadline.strftime("%H:%M:%S")}},
        auth=auth,
    )
    result["s4_patch_status"] = r.status_code

    verify = SessionLocal()
    reloaded_row4 = verify.query(models.SafetyDailyState).filter(models.SafetyDailyState.id == row4_id).first()
    result["s4_status_after"] = reloaded_row4.status
    result["s4_deadline_after"] = reloaded_row4.deadline_utc.isoformat()
    verify.close()

    # ── (5) no state exists today -> PATCH succeeds, no row is created ────
    db = SessionLocal()
    user5_id = make_user(db, "tok-same-day-5", initial_deadline)
    db.close()

    r = client.patch(
        f"/admin/safety/users/{{user5_id}}",
        json={{"daily_deadline": future_deadline.strftime("%H:%M:%S")}},
        auth=auth,
    )
    result["s5_patch_status"] = r.status_code

    verify = SessionLocal()
    result["s5_daily_state_count"] = (
        verify.query(models.SafetyDailyState).filter(models.SafetyDailyState.user_id == user5_id).count()
    )
    verify.close()

    # ── (6) recalculated deadline already passed -> row stays pending ─────
    db = SessionLocal()
    user6_id = make_user(db, "tok-same-day-6", initial_deadline)
    user6 = db.query(models.SafetyUser).filter(models.SafetyUser.id == user6_id).first()
    today6 = local_safety_date(user6, now)
    row6 = get_or_create_daily_state(db, user6, today6)
    db.commit()
    db.refresh(row6)
    row6_id = row6.id
    result["s6_status_before"] = row6.status
    db.close()

    r = client.patch(
        f"/admin/safety/users/{{user6_id}}",
        json={{"daily_deadline": past_deadline.strftime("%H:%M:%S")}},
        auth=auth,
    )
    result["s6_patch_status"] = r.status_code

    verify = SessionLocal()
    reloaded_user6 = verify.query(models.SafetyUser).filter(models.SafetyUser.id == user6_id).first()
    reloaded_row6 = verify.query(models.SafetyDailyState).filter(models.SafetyDailyState.id == row6_id).first()
    result["s6_status_after"] = reloaded_row6.status
    result["s6_deadline_after"] = reloaded_row6.deadline_utc.isoformat()
    result["s6_expected_deadline"] = local_deadline_utc(reloaded_user6, today6).replace(tzinfo=None).isoformat()
    verify.close()

    print(json.dumps(result))
    """
)


class AdminSafetySameDayDeadlineRecalcS8Tests(unittest.TestCase):
    """Reproduces the real main.app + admin_router + verify_admin wiring,
    plus the real safety_deadline.py daily-state helpers, end to end."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # let create_all build it fresh

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _run(self) -> dict:
        env = dict(os.environ)
        env["DATABASE_URL"] = f"sqlite:///{self.db_path}"
        env["ADMIN_USERNAME"] = _ADMIN_USER
        env["ADMIN_PASSWORD"] = _ADMIN_PASS
        result = subprocess.run(
            [sys.executable, "-c", _SCRIPT],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    # ── (1) today's pending row is recalculated in place ─────────────────

    def test_today_pending_state_deadline_is_recalculated(self):
        payload = self._run()
        self.assertEqual(payload["s1_patch_status"], 200)
        self.assertTrue(payload["s1_row_id_unchanged"])
        self.assertEqual(payload["s1_status_after"], "pending")
        self.assertEqual(payload["s1_deadline_after"], payload["s1_expected_deadline"])
        self.assertNotEqual(payload["s1_deadline_after"], payload["s1_deadline_before"])

    # ── (2) today's safe row is left untouched ────────────────────────────

    def test_today_safe_state_is_unchanged(self):
        payload = self._run()
        self.assertEqual(payload["s2_patch_status"], 200)
        self.assertEqual(payload["s2_status_after"], "safe")
        self.assertEqual(payload["s2_deadline_after"], payload["s2_deadline_before"])

    # ── (3) today's missed row is left untouched ──────────────────────────

    def test_today_missed_state_is_unchanged(self):
        payload = self._run()
        self.assertEqual(payload["s3_patch_status"], 200)
        self.assertEqual(payload["s3_status_after"], "missed")
        self.assertEqual(payload["s3_deadline_after"], payload["s3_deadline_before"])

    # ── (4) a past day's pending row is left untouched ────────────────────

    def test_past_day_pending_state_is_unchanged(self):
        payload = self._run()
        self.assertEqual(payload["s4_patch_status"], 200)
        self.assertEqual(payload["s4_status_before"], "pending")
        self.assertEqual(payload["s4_status_after"], "pending")
        self.assertEqual(payload["s4_deadline_after"], payload["s4_deadline_before"])

    # ── (5) no state exists today -> no row is created ────────────────────

    def test_no_state_today_creates_no_row(self):
        payload = self._run()
        self.assertEqual(payload["s5_patch_status"], 200)
        self.assertEqual(payload["s5_daily_state_count"], 0)

    # ── (6) recalculated deadline already past -> row stays pending ───────

    def test_recalculated_deadline_already_past_leaves_state_pending(self):
        payload = self._run()
        self.assertEqual(payload["s6_patch_status"], 200)
        self.assertEqual(payload["s6_status_before"], "pending")
        self.assertEqual(payload["s6_status_after"], "pending")
        self.assertEqual(payload["s6_deadline_after"], payload["s6_expected_deadline"])


if __name__ == "__main__":
    unittest.main()
