"""Regression tests for SHADZ Safety Engine v1 Phase S8 SafetyUser config
PATCH semantics (safety_admin.py — PATCH /admin/safety/users/{id}).

Covers fixes from two rounds of independent review of the initial S8
implementation:

1. Effective-date semantics for daily_deadline: SafetyDailyState.deadline_utc
   is computed once and persisted when a daily state row is *created*
   (safety_deadline.get_or_create_daily_state -> local_deadline_utc, both
   reused here, not duplicated). Changing SafetyUser.daily_deadline through
   the admin PATCH must never rewrite an already-created row's
   deadline_utc/status/history -- it can only affect rows created after the
   change. This file proves that directly against the real
   get_or_create_daily_state, not just by inspecting safety_admin.py's
   source (which never touches SafetyDailyState at all).

   NOTE: timezone deliberately does NOT get this same "future rows only"
   treatment and is not in this file's PATCH payloads at all -- unlike
   daily_deadline, timezone is read live and repeatedly throughout the
   engine (safety_deadline.local_safety_date() calls ZoneInfo(user.timezone)
   on every check-in/evaluator tick/S8 overview computation to decide which
   safety_date a UTC instant belongs to), so there is no safe effective-date
   story for it. It was removed from SafetyUserConfigUpdateRequest entirely;
   see test_admin_safety_backend_s8.py's
   test_timezone_is_not_writable_via_config_patch for that specific
   coverage.
2. early_reminder_minutes is bounded 0-1440 (a single calendar day) -- no
   existing repo contract defined a stricter bound.
3. An empty/no-op PATCH (no fields, or fields matching current values) must
   not write anything -- no updated_at bump, no commit -- so it can never
   look like a real configuration change in SafetyUser's own history.

Follows test_admin_safety_backend_s8.py's existing rule: exercising the
real main.app + admin_router + verify_admin wiring (HTTP Basic Auth) can
only be done through main.py, and no test imports main.py in-process (to
avoid touching the real shadz.db or leaking main.py's module-level
engine/Session state across tests) -- so this runs against main.app in a
subprocess with DATABASE_URL pointed at a throwaway temp SQLite file and
ADMIN_USERNAME/ADMIN_PASSWORD set explicitly for the subprocess only.
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ADMIN_USER = "test-admin-s8-config"
_ADMIN_PASS = "test-pass-s8-config"

_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys
    from datetime import date, datetime, timedelta, timezone
    from datetime import time as dt_time

    sys.path.insert(0, {REPO_ROOT!r})

    import main
    import models
    from database import SessionLocal
    from fastapi.testclient import TestClient
    from safety_deadline import get_or_create_daily_state, local_deadline_utc

    result = {{}}
    db = SessionLocal()

    now = datetime.now(timezone.utc)

    user = models.SafetyUser(
        display_name="S8 Config Semantics User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-s8-config-semantics", is_active=True,
        created_at=now - timedelta(days=3),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id

    # ── (1) create a pending SafetyDailyState under the OLD config ──────
    today = (now - timedelta(days=1)).date()
    # SQLite round-trips DateTime(timezone=True) values as naive (see
    # safety_deadline._as_aware_utc's docstring) -- compare against the
    # naive form throughout so this test isn't just re-asserting that known
    # SQLite behavior.
    old_deadline_utc = local_deadline_utc(user, today).replace(tzinfo=None)
    existing_row = get_or_create_daily_state(db, user, today)
    db.commit()
    db.refresh(existing_row)
    existing_row_id = existing_row.id
    result["old_deadline_utc"] = old_deadline_utc.isoformat()
    result["existing_row_deadline_utc_before_patch"] = existing_row.deadline_utc.isoformat()
    result["existing_row_status_before_patch"] = existing_row.status
    db.close()

    client = TestClient(main.app)
    auth = ({_ADMIN_USER!r}, {_ADMIN_PASS!r})

    # ── PATCH the user's daily_deadline only -- timezone is not part of
    # this route's contract at all (see SafetyUserConfigUpdateRequest) ───
    r = client.patch(
        f"/admin/safety/users/{{user_id}}",
        json={{"daily_deadline": "08:00:00"}},
        auth=auth,
    )
    result["patch_status"] = r.status_code
    result["patch_body"] = r.json()

    # ── existing row must be completely untouched ────────────────────────
    verify_db = SessionLocal()
    reloaded_user = verify_db.query(models.SafetyUser).filter(models.SafetyUser.id == user_id).first()
    reloaded_existing = (
        verify_db.query(models.SafetyDailyState)
        .filter(models.SafetyDailyState.id == existing_row_id)
        .first()
    )
    result["existing_row_deadline_utc_after_patch"] = reloaded_existing.deadline_utc.isoformat()
    result["existing_row_status_after_patch"] = reloaded_existing.status

    # ── a NEW day's row, created after the patch, must use the NEW config ──
    tomorrow = today + timedelta(days=1)
    new_expected_deadline_utc = local_deadline_utc(reloaded_user, tomorrow).replace(tzinfo=None)
    new_row = get_or_create_daily_state(verify_db, reloaded_user, tomorrow)
    verify_db.commit()
    verify_db.refresh(new_row)
    result["new_row_deadline_utc"] = new_row.deadline_utc.isoformat()
    result["new_expected_deadline_utc"] = new_expected_deadline_utc.isoformat()
    verify_db.close()

    # ── (2) early_reminder_minutes bound: 1440 accepted, 1441 rejected ──
    r = client.patch(f"/admin/safety/users/{{user_id}}", json={{"early_reminder_minutes": 1440}}, auth=auth)
    result["reminder_1440_status"] = r.status_code
    result["reminder_1440_body"] = r.json()

    r = client.patch(f"/admin/safety/users/{{user_id}}", json={{"early_reminder_minutes": 1441}}, auth=auth)
    result["reminder_1441_status"] = r.status_code

    r = client.patch(f"/admin/safety/users/{{user_id}}", json={{"early_reminder_minutes": -1}}, auth=auth)
    result["reminder_negative_status"] = r.status_code

    # ── (3) no-op PATCH: empty body must not write anything ─────────────
    r = client.get("/admin/safety/users", auth=auth)
    before = next(row for row in r.json() if row["id"] == user_id)

    pre_db = SessionLocal()
    pre_updated_at = (
        pre_db.query(models.SafetyUser).filter(models.SafetyUser.id == user_id).first().updated_at
    )
    pre_db.close()

    r = client.patch(f"/admin/safety/users/{{user_id}}", json={{}}, auth=auth)
    result["noop_empty_status"] = r.status_code
    result["noop_empty_body"] = r.json()

    post_db = SessionLocal()
    post_updated_at = (
        post_db.query(models.SafetyUser).filter(models.SafetyUser.id == user_id).first().updated_at
    )
    post_db.close()
    result["updated_at_unchanged_after_empty_patch"] = (pre_updated_at == post_updated_at)

    # ── no-op PATCH: every field explicitly repeated at its current value ──
    r = client.patch(
        f"/admin/safety/users/{{user_id}}",
        json={{
            "is_active": before["is_active"],
            "daily_deadline": before["daily_deadline"],
            "early_reminder_minutes": before["early_reminder_minutes"],
        }},
        auth=auth,
    )
    result["noop_matching_status"] = r.status_code

    post2_db = SessionLocal()
    post2_updated_at = (
        post2_db.query(models.SafetyUser).filter(models.SafetyUser.id == user_id).first().updated_at
    )
    post2_db.close()
    result["updated_at_unchanged_after_matching_patch"] = (pre_updated_at == post2_updated_at)

    # ── this route never touches SafetyDailyState/SafetyAlert/SafetyEmergency ──
    audit_db = SessionLocal()
    result["daily_state_count_after_all_patches"] = (
        audit_db.query(models.SafetyDailyState).filter(models.SafetyDailyState.user_id == user_id).count()
    )
    result["alert_count_after_all_patches"] = (
        audit_db.query(models.SafetyAlert).filter(models.SafetyAlert.user_id == user_id).count()
    )
    result["emergency_count_after_all_patches"] = (
        audit_db.query(models.SafetyEmergency).filter(models.SafetyEmergency.user_id == user_id).count()
    )
    audit_db.close()

    print(json.dumps(result))
    """
)


class AdminSafetyConfigSemanticsS8Tests(unittest.TestCase):
    """Reproduces the real main.app + admin_router + verify_admin wiring,
    plus the real safety_deadline.py daily-state creation logic, end to
    end."""

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

    # ── (1) effective-date semantics ─────────────────────────────────────

    def test_existing_daily_state_deadline_utc_is_not_rewritten_by_config_patch(self):
        payload = self._run()
        self.assertEqual(payload["patch_status"], 200)
        self.assertEqual(
            payload["existing_row_deadline_utc_after_patch"],
            payload["existing_row_deadline_utc_before_patch"],
        )
        self.assertEqual(
            payload["existing_row_deadline_utc_after_patch"], payload["old_deadline_utc"]
        )

    def test_existing_daily_state_status_is_not_rewritten_by_config_patch(self):
        payload = self._run()
        self.assertEqual(
            payload["existing_row_status_after_patch"], payload["existing_row_status_before_patch"]
        )
        self.assertEqual(payload["existing_row_status_after_patch"], "pending")

    def test_new_daily_state_created_after_patch_uses_new_config(self):
        payload = self._run()
        self.assertEqual(payload["new_row_deadline_utc"], payload["new_expected_deadline_utc"])
        # And it must genuinely differ from the old config's deadline instant
        # -- otherwise this test would pass even if the patch silently
        # failed to take effect at all.
        self.assertNotEqual(payload["new_row_deadline_utc"], payload["old_deadline_utc"])

    # ── (2) early_reminder_minutes domain bound ──────────────────────────

    def test_early_reminder_minutes_upper_bound_accepted(self):
        payload = self._run()
        self.assertEqual(payload["reminder_1440_status"], 200)
        self.assertEqual(payload["reminder_1440_body"]["early_reminder_minutes"], 1440)

    def test_early_reminder_minutes_above_upper_bound_rejected(self):
        payload = self._run()
        self.assertEqual(payload["reminder_1441_status"], 422)

    def test_early_reminder_minutes_negative_rejected(self):
        payload = self._run()
        self.assertEqual(payload["reminder_negative_status"], 422)

    # ── (3) no-op PATCH guard ────────────────────────────────────────────

    def test_empty_patch_is_a_200_no_op(self):
        payload = self._run()
        self.assertEqual(payload["noop_empty_status"], 200)

    def test_empty_patch_does_not_bump_updated_at(self):
        payload = self._run()
        self.assertTrue(payload["updated_at_unchanged_after_empty_patch"])

    def test_patch_with_all_fields_matching_current_values_does_not_bump_updated_at(self):
        payload = self._run()
        self.assertEqual(payload["noop_matching_status"], 200)
        self.assertTrue(payload["updated_at_unchanged_after_matching_patch"])

    def test_config_route_never_writes_other_safety_tables(self):
        payload = self._run()
        # Only the one SafetyDailyState row this test itself created via
        # get_or_create_daily_state (existing + new) -- the config PATCH
        # route must not have created/touched any daily state, alert, or
        # emergency row on its own.
        self.assertEqual(payload["daily_state_count_after_all_patches"], 2)
        self.assertEqual(payload["alert_count_after_all_patches"], 0)
        self.assertEqual(payload["emergency_count_after_all_patches"], 0)


if __name__ == "__main__":
    unittest.main()
