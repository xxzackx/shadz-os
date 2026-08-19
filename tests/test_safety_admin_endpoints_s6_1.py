"""Regression tests for Safety Engine v1 Phase S6.1 admin routes
(safety_admin.py — GET /admin/safety/users, PATCH
/admin/safety/users/{id}/telegram-chat-id).

register_safety_admin_routes wires these onto main.py's admin_router, which
applies HTTP Basic Auth (verify_admin) at the router level -- unlike
page_admin.py's/media_admin.py's own test files (test_page_admin.py,
test_media_admin_endpoints_ui3e_e.py), which register routes onto a bare
APIRouter with no auth dependency, deliberately scoped to route logic only
and not exercising verify_admin. Testing "auth required" here means
exercising the real main.app + admin_router + verify_admin wiring, which
only exists in main.py. Following test_safety_notify_orm_handoff_s6.py's
existing rule (no test imports main.py in-process, to avoid touching the
real shadz.db or leaking main.py's module-level engine/Session state across
tests), this runs against main.app in a subprocess with DATABASE_URL pointed
at a throwaway temp SQLite file and ADMIN_USERNAME/ADMIN_PASSWORD set
explicitly for the subprocess only.
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ADMIN_USER = "test-admin-s6-1"
_ADMIN_PASS = "test-pass-s6-1"

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
        display_name="Admin Route User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-admin-route-s6-1", is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    user_id = user.id
    db.close()

    client = TestClient(main.app)
    auth = ({_ADMIN_USER!r}, {_ADMIN_PASS!r})

    # ── auth required ────────────────────────────────────────────────
    r = client.get("/admin/safety/users")
    result["list_no_auth_status"] = r.status_code

    r = client.patch(
        f"/admin/safety/users/{{user_id}}/telegram-chat-id",
        json={{"telegram_chat_id": 1}},
    )
    result["patch_no_auth_status"] = r.status_code

    # ── list ─────────────────────────────────────────────────────────
    r = client.get("/admin/safety/users", auth=auth)
    result["list_status"] = r.status_code
    result["list_body"] = r.json()

    # ── set ──────────────────────────────────────────────────────────
    r = client.patch(
        f"/admin/safety/users/{{user_id}}/telegram-chat-id",
        json={{"telegram_chat_id": 123456}}, auth=auth,
    )
    result["set_status"] = r.status_code
    result["set_body"] = r.json()

    # ── explicit null clear ─────────────────────────────────────────
    r = client.patch(
        f"/admin/safety/users/{{user_id}}/telegram-chat-id",
        json={{"telegram_chat_id": None}}, auth=auth,
    )
    result["clear_status"] = r.status_code
    result["clear_body"] = r.json()

    # ── unknown SafetyUser -> 404 ───────────────────────────────────
    r = client.patch(
        "/admin/safety/users/999999/telegram-chat-id",
        json={{"telegram_chat_id": 1}}, auth=auth,
    )
    result["unknown_status"] = r.status_code

    # ── empty PATCH body -> 422, existing value left unchanged ──────
    r = client.patch(
        f"/admin/safety/users/{{user_id}}/telegram-chat-id",
        json={{"telegram_chat_id": 777}}, auth=auth,
    )
    result["preset_status"] = r.status_code
    r = client.patch(f"/admin/safety/users/{{user_id}}/telegram-chat-id", json={{}}, auth=auth)
    result["empty_body_status"] = r.status_code
    r = client.get("/admin/safety/users", auth=auth)
    result["after_empty_body_chat_id"] = next(
        u["telegram_chat_id"] for u in r.json() if u["id"] == user_id
    )

    print(json.dumps(result))
    """
)


class SafetyAdminEndpointsS61Tests(unittest.TestCase):
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

    def test_auth_required_for_list_and_patch(self):
        payload = self._run()
        self.assertEqual(payload["list_no_auth_status"], 401)
        self.assertEqual(payload["patch_no_auth_status"], 401)

    def test_list_returns_minimal_fields_only(self):
        payload = self._run()
        self.assertEqual(payload["list_status"], 200)
        self.assertEqual(len(payload["list_body"]), 1)
        row = payload["list_body"][0]
        # nfc_token and raw secure_token are deliberately never exposed by
        # this admin endpoint. S8 added timezone/daily_deadline/
        # early_reminder_minutes visibility -- see test_admin_safety_module_s8.py.
        # A later S8 UX fix added checkin_url, a derived, safe-to-share
        # artifact of secure_token (see test_admin_safety_checkin_link_and_timezone_s8.py).
        self.assertEqual(
            set(row.keys()),
            {
                "id", "display_name", "is_active", "telegram_chat_id",
                "timezone", "daily_deadline", "early_reminder_minutes",
                "checkin_url",
            },
        )
        self.assertEqual(row["display_name"], "Admin Route User")
        self.assertIsNone(row["telegram_chat_id"])

    def test_set_updates_telegram_chat_id(self):
        payload = self._run()
        self.assertEqual(payload["set_status"], 200)
        self.assertEqual(payload["set_body"]["telegram_chat_id"], 123456)

    def test_explicit_null_clears_telegram_chat_id(self):
        payload = self._run()
        self.assertEqual(payload["clear_status"], 200)
        self.assertIsNone(payload["clear_body"]["telegram_chat_id"])

    def test_unknown_safety_user_returns_404(self):
        payload = self._run()
        self.assertEqual(payload["unknown_status"], 404)

    def test_empty_patch_body_returns_422_and_leaves_value_unchanged(self):
        payload = self._run()
        self.assertEqual(payload["preset_status"], 200)
        self.assertEqual(payload["empty_body_status"], 422)
        self.assertEqual(payload["after_empty_body_chat_id"], 777)


if __name__ == "__main__":
    unittest.main()
