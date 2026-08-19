"""Regression tests for Safety Engine v1 Phase S7 SOS admin routes
(safety_admin.py — GET /admin/safety/emergencies, POST
/admin/safety/emergencies/{id}/acknowledge, POST
/admin/safety/emergencies/{id}/resolve).

Follows test_safety_admin_endpoints_s6_1.py's existing rule: exercising the
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

_ADMIN_USER = "test-admin-s7"
_ADMIN_PASS = "test-pass-s7"

_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys
    from datetime import time as dt_time

    sys.path.insert(0, {REPO_ROOT!r})

    import main
    import models
    from database import SessionLocal
    from fastapi.testclient import TestClient

    result = {{}}

    db = SessionLocal()
    user = models.SafetyUser(
        display_name="SOS Admin Route User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-sos-admin-route-s7", is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    user_id = user.id

    emergency = models.SafetyEmergency(user_id=user_id, status="open")
    db.add(emergency)
    db.commit()
    db.refresh(emergency)
    emergency_id = emergency.id

    second_user = models.SafetyUser(
        display_name="SOS Admin Route User 2", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-sos-admin-route-s7-2", is_active=True,
    )
    db.add(second_user)
    db.commit()
    db.refresh(second_user)
    resolved_emergency = models.SafetyEmergency(user_id=second_user.id, status="resolved")
    db.add(resolved_emergency)
    db.commit()
    db.refresh(resolved_emergency)
    resolved_emergency_id = resolved_emergency.id
    db.close()

    client = TestClient(main.app)
    auth = ({_ADMIN_USER!r}, {_ADMIN_PASS!r})

    # ── auth required (unauthorized/public caller cannot act) ──────────
    r = client.get("/admin/safety/emergencies")
    result["list_no_auth_status"] = r.status_code

    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/acknowledge")
    result["ack_no_auth_status"] = r.status_code

    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/resolve")
    result["resolve_no_auth_status"] = r.status_code

    # ── list (auditable history, includes already-resolved rows) ───────
    r = client.get("/admin/safety/emergencies", auth=auth)
    result["list_status"] = r.status_code
    result["list_ids"] = sorted(row["id"] for row in r.json())

    # ── locked lifecycle: resolving a still-open SOS is rejected 409 ───
    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/resolve", auth=auth)
    result["resolve_while_open_status"] = r.status_code
    r = client.get("/admin/safety/emergencies", auth=auth)
    result["status_after_rejected_resolve"] = next(
        row["status"] for row in r.json() if row["id"] == emergency_id
    )

    # ── acknowledge ──────────────────────────────────────────────────
    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/acknowledge", auth=auth)
    result["ack_status"] = r.status_code
    result["ack_body"] = r.json()

    # ── repeated acknowledge is safe ────────────────────────────────
    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/acknowledge", auth=auth)
    result["ack_repeat_status"] = r.status_code
    result["ack_repeat_body"] = r.json()

    # ── resolve (now valid: acknowledged -> resolved) ─────────────────
    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/resolve", auth=auth)
    result["resolve_status"] = r.status_code
    result["resolve_body"] = r.json()

    # ── repeated resolve is safe ─────────────────────────────────────
    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/resolve", auth=auth)
    result["resolve_repeat_status"] = r.status_code
    result["resolve_repeat_body"] = r.json()

    # ── acknowledge after resolve does not regress status ────────────
    r = client.post(f"/admin/safety/emergencies/{{emergency_id}}/acknowledge", auth=auth)
    result["ack_after_resolve_status"] = r.status_code
    result["ack_after_resolve_body"] = r.json()

    # ── unknown emergency -> 404 ─────────────────────────────────────
    r = client.post("/admin/safety/emergencies/999999/acknowledge", auth=auth)
    result["unknown_ack_status"] = r.status_code
    r = client.post("/admin/safety/emergencies/999999/resolve", auth=auth)
    result["unknown_resolve_status"] = r.status_code

    # ── TOCTOU race: resolve_sos returns a non-'resolved' row (e.g. a
    # concurrent acknowledge landed between this call's failed UPDATE and
    # its re-query) -- the route must fail closed with 409, not 200, even
    # though the row is no longer 'open'.
    from unittest.mock import patch
    import safety_admin

    race_db = SessionLocal()
    race_emergency = models.SafetyEmergency(user_id=user_id, status="acknowledged")
    race_db.add(race_emergency)
    race_db.commit()
    race_db.refresh(race_emergency)
    race_emergency_id = race_emergency.id

    with patch.object(safety_admin, "resolve_sos", return_value=race_emergency):
        r = client.post(f"/admin/safety/emergencies/{{race_emergency_id}}/resolve", auth=auth)
    result["resolve_toctou_race_status"] = r.status_code
    race_db.close()

    print(json.dumps(result))
    """
)


class SafetyAdminSOSEndpointsS7Tests(unittest.TestCase):
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

    def test_auth_required_for_list_acknowledge_and_resolve(self):
        payload = self._run()
        self.assertEqual(payload["list_no_auth_status"], 401)
        self.assertEqual(payload["ack_no_auth_status"], 401)
        self.assertEqual(payload["resolve_no_auth_status"], 401)

    def test_list_includes_historical_and_open_emergencies(self):
        payload = self._run()
        self.assertEqual(payload["list_status"], 200)
        self.assertEqual(len(payload["list_ids"]), 2)

    def test_resolving_a_still_open_sos_is_rejected_with_409(self):
        # Locked S7 lifecycle: open -> resolved directly is invalid; the SOS
        # must be acknowledged first.
        payload = self._run()
        self.assertEqual(payload["resolve_while_open_status"], 409)
        self.assertEqual(payload["status_after_rejected_resolve"], "open")

    def test_acknowledge_sets_acknowledged_not_resolved(self):
        payload = self._run()
        self.assertEqual(payload["ack_status"], 200)
        self.assertEqual(payload["ack_body"]["status"], "acknowledged")
        self.assertIsNotNone(payload["ack_body"]["acknowledged_at"])
        self.assertIsNone(payload["ack_body"]["resolved_at"])

    def test_repeated_acknowledge_is_idempotent(self):
        payload = self._run()
        self.assertEqual(payload["ack_repeat_status"], 200)
        self.assertEqual(payload["ack_repeat_body"]["status"], "acknowledged")
        self.assertEqual(
            payload["ack_repeat_body"]["acknowledged_at"], payload["ack_body"]["acknowledged_at"]
        )

    def test_resolve_sets_resolved(self):
        payload = self._run()
        self.assertEqual(payload["resolve_status"], 200)
        self.assertEqual(payload["resolve_body"]["status"], "resolved")
        self.assertIsNotNone(payload["resolve_body"]["resolved_at"])

    def test_repeated_resolve_is_idempotent(self):
        payload = self._run()
        self.assertEqual(payload["resolve_repeat_status"], 200)
        self.assertEqual(payload["resolve_repeat_body"]["status"], "resolved")
        self.assertEqual(
            payload["resolve_repeat_body"]["resolved_at"], payload["resolve_body"]["resolved_at"]
        )

    def test_acknowledge_after_resolve_does_not_regress_status(self):
        payload = self._run()
        self.assertEqual(payload["ack_after_resolve_status"], 200)
        self.assertEqual(payload["ack_after_resolve_body"]["status"], "resolved")

    def test_unknown_emergency_returns_404_for_both_actions(self):
        payload = self._run()
        self.assertEqual(payload["unknown_ack_status"], 404)
        self.assertEqual(payload["unknown_resolve_status"], 404)

    def test_resolve_fails_closed_on_toctou_race_returning_non_resolved_row(self):
        # If resolve_sos returns a row that is not 'resolved' (e.g. a
        # concurrent acknowledge won the race between this call's failed
        # UPDATE and its re-query, leaving it 'acknowledged' rather than
        # 'open'), the route must still reject with 409 -- checking only
        # for status == 'open' would have wrongly returned 200 here.
        payload = self._run()
        self.assertEqual(payload["resolve_toctou_race_status"], 409)


if __name__ == "__main__":
    unittest.main()
