"""Regression tests for SHADZ Safety Engine v1 Phase S8 live-testing UX
fixes: the admin-facing Safety Check-in Link (safety_admin.py --
SafetyUserOut.checkin_url) and Admin-Panel-only Cambodia-time display
(static/admin.html -- fmtSafetyTime).

1. Check-in Link: SafetyUserOut gains checkin_url, the full canonical
   public Safety entry URL (GET /safety/c/{secure_token}, the locked S2
   route -- unchanged) so Admin can copy it into the normal Redirect
   Engine's destination_url. The raw secure_token and nfc_token are never
   serialized by any Safety admin schema -- checkin_url is the only
   derived, safe-to-share artifact of secure_token. Base URL follows
   media_admin._make_public_url's existing env-var-with-default pattern
   (SHADZ_PUBLIC_BASE_URL), so this file also proves the override actually
   takes effect rather than being a dead code path.
2. Cambodia time: the Admin Panel formats Safety timestamps in
   Asia/Phnom_Penh for display only -- the backend keeps storing/
   transmitting server-authoritative UTC untouched (this file asserts the
   raw API response is still plain UTC ISO text, with no timezone
   conversion happening server-side at all).

The backend half follows test_admin_safety_backend_s8.py's existing rule:
exercising the real main.app + admin_router + verify_admin wiring (HTTP
Basic Auth) can only be done through main.py, and no test imports main.py
in-process (to avoid touching the real shadz.db or leaking main.py's
module-level engine/Session state across tests) -- so it runs against
main.app in a subprocess with DATABASE_URL pointed at a throwaway temp
SQLite file and ADMIN_USERNAME/ADMIN_PASSWORD set explicitly for the
subprocess only. The UI half follows test_admin_shell_ui3b.py's existing
lightweight style: read static/admin.html directly and assert on
structural/JS markers.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ADMIN_HTML_PATH = os.path.join(REPO_ROOT, "static", "admin.html")

_ADMIN_USER = "test-admin-s8-checkin-link"
_ADMIN_PASS = "test-pass-s8-checkin-link"

_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys
    from datetime import datetime, timezone
    from datetime import time as dt_time

    sys.path.insert(0, {REPO_ROOT!r})

    import main
    import models
    from database import SessionLocal
    from fastapi.testclient import TestClient

    result = {{}}
    db = SessionLocal()

    now = datetime.now(timezone.utc)

    user = models.SafetyUser(
        display_name="S8 Checkin Link User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-s8-checkin-link", is_active=True,
        created_at=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id
    result["raw_secure_token"] = user.secure_token
    result["raw_nfc_token"] = user.nfc_token

    emergency = models.SafetyEmergency(
        user_id=user_id, status="open", triggered_at=now, latitude=1.0, longitude=1.0,
    )
    db.add(emergency)
    db.commit()
    db.close()

    client = TestClient(main.app)
    auth = ({_ADMIN_USER!r}, {_ADMIN_PASS!r})

    # ── checkin_url with default base URL ────────────────────────────────
    r = client.get("/admin/safety/users", auth=auth)
    result["users_status"] = r.status_code
    row = next(row for row in r.json() if row["id"] == user_id)
    result["users_row"] = row

    # ── checkin_url present on the config-PATCH response too ─────────────
    r = client.patch(
        f"/admin/safety/users/{{user_id}}",
        json={{"early_reminder_minutes": 45}},
        auth=auth,
    )
    result["patch_status"] = r.status_code
    result["patch_row"] = r.json()

    # ── backend timestamps remain plain UTC ISO -- no server-side
    # Cambodia-time conversion, no offset suffix added ───────────────────
    r = client.get("/admin/safety/emergencies", auth=auth)
    result["emergencies_status"] = r.status_code
    result["emergency_row"] = next(row for row in r.json() if row["user_id"] == user_id)

    print(json.dumps(result))
    """
)


class AdminSafetyCheckinLinkBackendS8Tests(unittest.TestCase):
    """Reproduces the real main.app + admin_router + verify_admin wiring
    end to end."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.db_path)  # let create_all build it fresh

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def _run(self, env_overrides=None) -> dict:
        env = dict(os.environ)
        env["DATABASE_URL"] = f"sqlite:///{self.db_path}"
        env["ADMIN_USERNAME"] = _ADMIN_USER
        env["ADMIN_PASSWORD"] = _ADMIN_PASS
        if env_overrides:
            env.update(env_overrides)
        result = subprocess.run(
            [sys.executable, "-c", _SCRIPT],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    # ── checkin_url present, correct, and derived from secure_token ─────

    def test_users_list_contains_full_checkin_url(self):
        payload = self._run()
        self.assertEqual(payload["users_status"], 200)
        row = payload["users_row"]
        self.assertIn("checkin_url", row)
        expected = f"https://shadz.io/safety/c/{payload['raw_secure_token']}"
        self.assertEqual(row["checkin_url"], expected)

    def test_config_patch_response_also_contains_checkin_url(self):
        payload = self._run()
        self.assertEqual(payload["patch_status"], 200)
        row = payload["patch_row"]
        self.assertIn("checkin_url", row)
        self.assertIn(payload["raw_secure_token"], row["checkin_url"])

    def test_checkin_url_base_overridable_via_env_var(self):
        payload = self._run(env_overrides={"SHADZ_PUBLIC_BASE_URL": "https://staging.example.org/"})
        row = payload["users_row"]
        self.assertEqual(
            row["checkin_url"],
            f"https://staging.example.org/safety/c/{payload['raw_secure_token']}",
        )

    def test_checkin_url_preserves_locked_s2_route_shape(self):
        payload = self._run()
        row = payload["users_row"]
        self.assertRegex(row["checkin_url"], r"^https://[^/]+/safety/c/[^/]+$")

    # ── raw tokens never exposed ──────────────────────────────────────────

    def test_raw_secure_token_not_in_users_response(self):
        payload = self._run()
        row = payload["users_row"]
        self.assertNotIn("secure_token", row)
        # And the actual token value must not leak under some other key either.
        self.assertNotIn(payload["raw_secure_token"], json.dumps(row).replace(row["checkin_url"], ""))

    def test_raw_nfc_token_not_in_users_response(self):
        payload = self._run()
        row = payload["users_row"]
        self.assertNotIn("nfc_token", row)
        self.assertNotIn(payload["raw_nfc_token"], json.dumps(row))

    def test_raw_tokens_not_in_config_patch_response(self):
        payload = self._run()
        row = payload["patch_row"]
        self.assertNotIn("secure_token", row)
        self.assertNotIn("nfc_token", row)

    # ── backend storage/serialization unaffected by Admin-Panel display ──

    def test_backend_emergency_timestamp_is_plain_utc_iso(self):
        # No "Cambodia"/offset conversion happens server-side -- proves the
        # Cambodia-time requirement was implemented purely as an Admin
        # Panel display concern, not a backend/storage change.
        payload = self._run()
        self.assertEqual(payload["emergencies_status"], 200)
        triggered_at = payload["emergency_row"]["triggered_at"]
        self.assertNotIn("Cambodia", triggered_at)
        self.assertNotIn("+07:00", triggered_at)
        self.assertRegex(triggered_at, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


class AdminSafetyCheckinLinkUITests(unittest.TestCase):
    """Static structural checks on static/admin.html, matching
    test_admin_safety_module_s8.py's existing style."""

    @classmethod
    def setUpClass(cls):
        with open(ADMIN_HTML_PATH, "r", encoding="utf-8") as f:
            cls.html = f.read()

    # ── Check-in Link UI ─────────────────────────────────────────────────

    def test_check_in_link_label_and_copy_button_present(self):
        build_fn = re.search(
            r"function buildSafetyUserCard\(u\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        body = build_fn.group(0)
        self.assertIn("Check-in Link", body)
        self.assertIn("Copy Link", body)
        self.assertIn("escVal(u.checkin_url)", body)
        self.assertIn("copySafetyCheckinLink", body)

    def test_check_in_link_field_is_read_only(self):
        build_fn = re.search(
            r"function buildSafetyUserCard\(u\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        checkin_row = re.search(
            r'<span class="stats-label">Check-in Link</span>.*?/>', build_fn.group(0), re.DOTALL
        )
        self.assertIsNotNone(checkin_row)
        self.assertIn("readonly", checkin_row.group(0))

    def test_no_regenerate_or_edit_action_for_checkin_link(self):
        self.assertNotIn("regenerateSafetyCheckinLink", self.html)
        self.assertNotIn("regenerateCheckinUrl", self.html)
        self.assertNotIn("editSafetyCheckinLink", self.html)

    def test_copy_link_uses_clipboard_api(self):
        copy_fn = re.search(
            r"async function copySafetyCheckinLink\(.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(copy_fn)
        self.assertIn("navigator.clipboard.writeText", copy_fn.group(0))

    def test_no_raw_token_field_names_referenced_in_ui(self):
        self.assertNotIn("nfc_token", self.html)
        self.assertNotIn("secure_token", self.html)

    # ── Cambodia-time formatting ──────────────────────────────────────────

    def test_cambodia_time_formatter_defined(self):
        fmt_fn = re.search(r"function fmtSafetyTime\(.*?\n    \}", self.html, re.DOTALL)
        self.assertIsNotNone(fmt_fn)
        body = fmt_fn.group(0)
        self.assertIn("Asia/Phnom_Penh", body)
        self.assertIn("Cambodia", body)

    def test_all_required_safety_timestamps_use_cambodia_formatter(self):
        # check-in, alert triggered/resolved, late-checkin, and SOS
        # triggered/acknowledged/resolved -- every currently-rendered S8
        # Safety audit timestamp.
        for call in (
            "fmtSafetyTime(c.checked_in_at)",
            "fmtSafetyTime(a.triggered_at)",
            "fmtSafetyTime(a.resolved_at)",
            "fmtSafetyTime(e.triggered_at)",
            "fmtSafetyTime(e.acknowledged_at)",
            "fmtSafetyTime(e.resolved_at)",
        ):
            self.assertIn(call, self.html)
        # Late-checkin alert triggered_at shares the same
        # `a.triggered_at` render call as the missed-checkin alert loop --
        # confirm that loop body itself references fmtSafetyTime.
        late_fn = re.search(
            r"async function loadSafetyLateCheckinAlerts\(\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(late_fn)
        self.assertIn("fmtSafetyTime(a.triggered_at)", late_fn.group(0))

    def test_no_raw_unformatted_safety_timestamp_left(self):
        # Every one of these previously-raw esc(x.<ts>) calls must now be
        # routed through fmtSafetyTime -- regression guard against a future
        # change accidentally reverting to raw display.
        for raw_call in (
            "esc(c.checked_in_at)", "esc(a.triggered_at)", "esc(a.resolved_at)",
            "esc(e.triggered_at)", "esc(e.acknowledged_at)", "esc(e.resolved_at)",
        ):
            self.assertNotIn(raw_call, self.html)

    def test_daily_deadline_config_input_unaffected_by_cambodia_formatter(self):
        # SafetyUser.daily_deadline is plain config (a time-of-day, not a
        # UTC instant) -- it must keep using escVal() directly, never routed
        # through fmtSafetyTime (which only makes sense for UTC timestamps).
        build_fn = re.search(
            r"function buildSafetyUserCard\(u\) \{.*?\n    \}", self.html, re.DOTALL
        )
        self.assertIsNotNone(build_fn)
        self.assertIn("escVal(u.daily_deadline)", build_fn.group(0))
        self.assertNotIn("fmtSafetyTime(u.daily_deadline)", build_fn.group(0))


if __name__ == "__main__":
    unittest.main()
