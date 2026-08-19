"""Regression tests for SHADZ Safety Engine v1 Phase S8 backend admin
routes (safety_admin.py — GET /admin/safety/overview, PATCH
/admin/safety/users/{id}, GET /admin/safety/checkins, GET
/admin/safety/daily-states, GET /admin/safety/alerts, GET
/admin/safety/late-checkin-alerts).

S8's locked scope: Admin Panel = Safety management / visibility /
configuration / audit / history (this file); Admin Telegram remains
immediate incident response only (unchanged). These routes are all
read-only projections of existing tables, or (for the new user-config PATCH)
a plain attribute assignment -- none of them introduce a new state machine,
and none duplicate the existing SOS/late-checkin/missed-checkin transition
logic already covered by test_safety_admin_sos_endpoints_s7.py and
test_safety_missed_checkin_resolution_s7.py.

Follows test_safety_admin_sos_endpoints_s7.py's existing rule: exercising
the real main.app + admin_router + verify_admin wiring (HTTP Basic Auth) can
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

_ADMIN_USER = "test-admin-s8"
_ADMIN_PASS = "test-pass-s8"

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

    result = {{}}
    db = SessionLocal()

    now = datetime.now(timezone.utc)

    # Active user, eligible today, with an existing SAFE day + a check-in
    # (exercises checkins/daily-states history + today's overview counts).
    active_user = models.SafetyUser(
        display_name="S8 Active User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-s8-active", is_active=True,
        created_at=now - timedelta(days=2),
    )
    db.add(active_user)
    db.commit()
    db.refresh(active_user)

    checkin = models.SafetyCheckIn(
        user_id=active_user.id, checked_in_at=now, latitude=40.0, longitude=-73.0,
        accuracy_m=5.0, source="public_web",
    )
    db.add(checkin)
    db.commit()
    db.refresh(checkin)

    today = now.date()
    daily_state = models.SafetyDailyState(
        user_id=active_user.id, safety_date=today, status="safe",
        deadline_utc=now + timedelta(hours=1), checkin_id=checkin.id,
        evaluated_at=now,
    )
    db.add(daily_state)
    db.commit()

    # A second active user with an open missed-checkin SafetyAlert (exercises
    # overview's open_missed_checkin_alerts count + /safety/alerts history).
    alert_user = models.SafetyUser(
        display_name="S8 Missed User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-s8-missed", is_active=True,
        created_at=now - timedelta(days=2),
    )
    db.add(alert_user)
    db.commit()
    db.refresh(alert_user)

    missed_state = models.SafetyDailyState(
        user_id=alert_user.id, safety_date=today, status="missed",
        deadline_utc=now - timedelta(hours=1), evaluated_at=now,
    )
    db.add(missed_state)
    alert = models.SafetyAlert(
        user_id=alert_user.id, safety_date=today, alert_type="missed_checkin", status="open",
        triggered_at=now,
    )
    db.add(alert)
    db.commit()

    # An open SOS (exercises overview's active_sos_incidents count).
    emergency = models.SafetyEmergency(user_id=alert_user.id, status="open")
    db.add(emergency)
    db.commit()

    # A late-checkin alert (exercises /safety/late-checkin-alerts history).
    late_checkin = models.SafetyCheckIn(
        user_id=alert_user.id, checked_in_at=now, latitude=1.0, longitude=1.0,
        accuracy_m=1.0, source="public_web",
    )
    db.add(late_checkin)
    db.commit()
    db.refresh(late_checkin)
    late_alert = models.SafetyLateCheckinAlert(
        user_id=alert_user.id, safety_date=today, checkin_id=late_checkin.id, triggered_at=now,
    )
    db.add(late_alert)
    db.commit()

    # An inactive user -- must not count toward overview's active_safety_users
    # or today counts, and must not be excluded from /safety/users visibility.
    inactive_user = models.SafetyUser(
        display_name="S8 Inactive User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-s8-inactive", is_active=False,
        created_at=now - timedelta(days=2),
    )
    db.add(inactive_user)
    db.commit()
    db.refresh(inactive_user)

    active_user_id = active_user.id
    alert_user_id = alert_user.id
    inactive_user_id = inactive_user.id
    db.close()

    client = TestClient(main.app)
    auth = ({_ADMIN_USER!r}, {_ADMIN_PASS!r})

    # ── auth required on every new S8 route ─────────────────────────────
    for path, method in [
        ("/admin/safety/overview", "get"),
        ("/admin/safety/checkins", "get"),
        ("/admin/safety/daily-states", "get"),
        ("/admin/safety/alerts", "get"),
        ("/admin/safety/late-checkin-alerts", "get"),
    ]:
        r = getattr(client, method)(path)
        result[f"noauth_{{path}}"] = r.status_code

    r = client.patch(f"/admin/safety/users/{{active_user_id}}", json={{"is_active": False}})
    result["noauth_patch_config"] = r.status_code

    # ── overview ─────────────────────────────────────────────────────
    r = client.get("/admin/safety/overview", auth=auth)
    result["overview_status"] = r.status_code
    result["overview_body"] = r.json()

    # ── checkins / daily-states / alerts / late-checkin-alerts history ──
    r = client.get("/admin/safety/checkins", auth=auth)
    result["checkins_status"] = r.status_code
    result["checkins_body"] = r.json()

    r = client.get("/admin/safety/daily-states", auth=auth)
    result["daily_states_status"] = r.status_code
    result["daily_states_body"] = r.json()

    r = client.get("/admin/safety/alerts", auth=auth)
    result["alerts_status"] = r.status_code
    result["alerts_body"] = r.json()

    r = client.get("/admin/safety/late-checkin-alerts", auth=auth)
    result["late_alerts_status"] = r.status_code
    result["late_alerts_body"] = r.json()

    # ── users list now includes config fields ───────────────────────────
    r = client.get("/admin/safety/users", auth=auth)
    result["users_status"] = r.status_code
    result["users_body"] = r.json()

    # ── config PATCH: partial update, only touches given fields ─────────
    r = client.patch(
        f"/admin/safety/users/{{active_user_id}}",
        json={{"early_reminder_minutes": 45}},
        auth=auth,
    )
    result["patch_partial_status"] = r.status_code
    result["patch_partial_body"] = r.json()

    # ── config PATCH: activate/deactivate ────────────────────────────────
    r = client.patch(
        f"/admin/safety/users/{{active_user_id}}", json={{"is_active": False}}, auth=auth
    )
    result["patch_deactivate_status"] = r.status_code
    result["patch_deactivate_body"] = r.json()

    # ── config PATCH: daily_deadline update ───────────────────────────────
    r = client.patch(
        f"/admin/safety/users/{{active_user_id}}",
        json={{"daily_deadline": "22:30:00"}},
        auth=auth,
    )
    result["patch_deadline_status"] = r.status_code
    result["patch_deadline_body"] = r.json()

    # ── config PATCH: timezone is not a writable field -- sending it must
    # fail closed with 422 (extra="forbid"), not be silently ignored ────────
    r = client.get("/admin/safety/users", auth=auth)
    timezone_before_attempt = next(
        row["timezone"] for row in r.json() if row["id"] == active_user_id
    )
    r = client.patch(
        f"/admin/safety/users/{{active_user_id}}",
        json={{"timezone": "America/New_York"}},
        auth=auth,
    )
    result["patch_timezone_attempt_status"] = r.status_code
    result["timezone_before_attempt"] = timezone_before_attempt

    r = client.get("/admin/safety/users", auth=auth)
    result["timezone_after_rejected_attempt"] = next(
        row["timezone"] for row in r.json() if row["id"] == active_user_id
    )

    # ── config PATCH: any unknown field also fails closed with 422 ──────
    r = client.patch(
        f"/admin/safety/users/{{active_user_id}}",
        json={{"not_a_real_field": 123}},
        auth=auth,
    )
    result["patch_unknown_field_status"] = r.status_code

    # ── config PATCH: negative early_reminder_minutes rejected ──────────
    r = client.patch(
        f"/admin/safety/users/{{active_user_id}}",
        json={{"early_reminder_minutes": -5}},
        auth=auth,
    )
    result["patch_negative_minutes_status"] = r.status_code

    # ── config PATCH: unknown user -> 404 ────────────────────────────────
    r = client.patch("/admin/safety/users/999999", json={{"is_active": True}}, auth=auth)
    result["patch_unknown_status"] = r.status_code

    # ── telegram-chat-id route (S6.1) still works unchanged ─────────────
    r = client.patch(
        f"/admin/safety/users/{{active_user_id}}/telegram-chat-id",
        json={{"telegram_chat_id": 555}},
        auth=auth,
    )
    result["telegram_route_status"] = r.status_code
    result["telegram_route_body"] = r.json()

    print(json.dumps(result))
    """
)


class AdminSafetyBackendS8Tests(unittest.TestCase):
    """Reproduces the real main.app + admin_router + verify_admin wiring
    end to end, once per admin-route behavior."""

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

    # ── auth boundary ────────────────────────────────────────────────

    def test_all_new_routes_require_auth(self):
        payload = self._run()
        for path in (
            "/admin/safety/overview",
            "/admin/safety/checkins",
            "/admin/safety/daily-states",
            "/admin/safety/alerts",
            "/admin/safety/late-checkin-alerts",
        ):
            self.assertEqual(payload[f"noauth_{path}"], 401, path)
        self.assertEqual(payload["noauth_patch_config"], 401)

    # ── overview ─────────────────────────────────────────────────────

    def test_overview_counts_active_users_only(self):
        payload = self._run()
        self.assertEqual(payload["overview_status"], 200)
        # 2 active users (active_user, alert_user); inactive_user excluded.
        self.assertEqual(payload["overview_body"]["active_safety_users"], 2)

    def test_overview_today_breakdown_reflects_daily_states(self):
        payload = self._run()
        body = payload["overview_body"]
        self.assertEqual(body["today_safe"], 1)
        self.assertEqual(body["today_missed"], 1)
        self.assertEqual(body["today_pending"], 0)
        self.assertEqual(body["today_no_state_yet"], 0)

    def test_overview_open_missed_checkin_alert_count(self):
        payload = self._run()
        self.assertEqual(payload["overview_body"]["open_missed_checkin_alerts"], 1)

    def test_overview_active_sos_incident_count(self):
        payload = self._run()
        self.assertEqual(payload["overview_body"]["active_sos_incidents"], 1)

    # ── check-in / daily-state / alert / late-alert history ─────────────

    def test_checkins_history_includes_gps(self):
        payload = self._run()
        self.assertEqual(payload["checkins_status"], 200)
        row = payload["checkins_body"][0]
        self.assertIn("latitude", row)
        self.assertIn("longitude", row)
        self.assertIn("accuracy_m", row)
        self.assertEqual(len(payload["checkins_body"]), 2)

    def test_daily_states_history_includes_status_and_user(self):
        payload = self._run()
        self.assertEqual(payload["daily_states_status"], 200)
        statuses = {row["status"] for row in payload["daily_states_body"]}
        self.assertEqual(statuses, {"safe", "missed"})

    def test_alerts_history_excludes_internal_fields(self):
        payload = self._run()
        self.assertEqual(payload["alerts_status"], 200)
        row = payload["alerts_body"][0]
        self.assertNotIn("telegram_message_id", row)
        self.assertNotIn("delivery_claimed_at", row)
        self.assertEqual(row["alert_type"], "missed_checkin")
        self.assertEqual(row["status"], "open")

    def test_late_checkin_alerts_history_excludes_internal_fields(self):
        payload = self._run()
        self.assertEqual(payload["late_alerts_status"], 200)
        row = payload["late_alerts_body"][0]
        self.assertNotIn("delivery_claimed_at", row)
        self.assertIn("checkin_id", row)

    # ── users list config visibility ─────────────────────────────────────

    def test_users_list_exposes_config_fields_not_tokens(self):
        payload = self._run()
        self.assertEqual(payload["users_status"], 200)
        row = payload["users_body"][0]
        for field in ("timezone", "daily_deadline", "early_reminder_minutes"):
            self.assertIn(field, row)
        for internal_field in ("nfc_token", "secure_token"):
            self.assertNotIn(internal_field, row)

    # ── config PATCH ────────────────────────────────────────────────────

    def test_partial_patch_only_changes_given_field(self):
        payload = self._run()
        self.assertEqual(payload["patch_partial_status"], 200)
        body = payload["patch_partial_body"]
        self.assertEqual(body["early_reminder_minutes"], 45)
        self.assertTrue(body["is_active"])  # untouched by this partial patch

    def test_patch_can_deactivate_user(self):
        payload = self._run()
        self.assertEqual(payload["patch_deactivate_status"], 200)
        self.assertFalse(payload["patch_deactivate_body"]["is_active"])

    def test_patch_updates_daily_deadline(self):
        payload = self._run()
        self.assertEqual(payload["patch_deadline_status"], 200)
        self.assertEqual(payload["patch_deadline_body"]["daily_deadline"], "22:30:00")

    def test_timezone_patch_fails_closed_with_422(self):
        # Locked S8 v1 rule: timezone is read live and repeatedly throughout
        # the deadline engine (safety_deadline.local_safety_date), unlike
        # daily_deadline, so there is no safe "applies only to future rows"
        # story for it -- it must not be a field this route can change, and
        # sending it must fail closed (422) rather than being silently
        # ignored, so a caller can never mistake a no-op for success.
        payload = self._run()
        self.assertEqual(payload["patch_timezone_attempt_status"], 422)

    def test_timezone_unchanged_after_rejected_patch(self):
        payload = self._run()
        self.assertEqual(
            payload["timezone_after_rejected_attempt"], payload["timezone_before_attempt"]
        )
        self.assertNotEqual(payload["timezone_before_attempt"], "America/New_York")

    def test_unknown_field_in_config_patch_fails_closed_with_422(self):
        payload = self._run()
        self.assertEqual(payload["patch_unknown_field_status"], 422)

    def test_negative_early_reminder_minutes_rejected(self):
        payload = self._run()
        self.assertEqual(payload["patch_negative_minutes_status"], 422)

    def test_patch_unknown_user_returns_404(self):
        payload = self._run()
        self.assertEqual(payload["patch_unknown_status"], 404)

    # ── existing S6.1 telegram-chat-id route unaffected ──────────────────

    def test_telegram_chat_id_route_still_works(self):
        payload = self._run()
        self.assertEqual(payload["telegram_route_status"], 200)
        self.assertEqual(payload["telegram_route_body"]["telegram_chat_id"], 555)


if __name__ == "__main__":
    unittest.main()
