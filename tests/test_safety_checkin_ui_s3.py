"""Regression tests for Safety Engine v1 Phase S3 (Safety Check-in UI +
Mandatory GPS + SOS UI — GET /safety/c/{secure_token}).

Mirrors the S2 test harness: a minimal FastAPI app registers only the
safety_public.serve_safety_entry route with get_db overridden to an
isolated in-memory SQLite database. Never imports main.py.

S3 only upgrades the rendered HTML/JS -- it adds no server-side Safety
writes, so these tests focus on the server-rendered contract: the S3 UI
elements are present, mandatory-geolocation gating is wired client-side,
and every S2 guarantee (secure-token routing, inactive==unknown 404,
zero DB mutation on GET, HTML escaping) still holds.
"""
import os
import sys
import unittest
from datetime import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import models
from database import Base, get_db
from safety_public import serve_safety_entry


class SafetyCheckInUIS3Tests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.SessionLocal = SessionLocal

        app = FastAPI()

        @app.get("/safety/c/{secure_token}")
        def safety_entry(secure_token: str, db=Depends(get_db)):
            return serve_safety_entry(secure_token, db)

        def _override_get_db():
            db = SessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = _override_get_db
        self.client = TestClient(app)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _make_user(self, nfc_token="nfc-1", is_active=True, **kwargs):
        user = models.SafetyUser(
            display_name=kwargs.pop("display_name", "Alice"),
            timezone="America/New_York",
            daily_deadline=time(21, 0),
            early_reminder_minutes=30,
            nfc_token=nfc_token,
            is_active=is_active,
            **kwargs,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    # ── S3 UI presence ──────────────────────────────────────────────────

    def test_valid_active_page_renders_200_html(self):
        user = self._make_user(display_name="Alice Safe")
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])

    def test_im_safe_action_present(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertIn('id="safe-btn"', resp.text)
        self.assertIn("I&#39;M SAFE", resp.text)

    def test_sos_action_present_and_distinct_from_safe_action(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertIn('id="sos-btn"', resp.text)
        self.assertIn("SOS", resp.text)
        self.assertNotEqual(
            resp.text.index('id="sos-btn"'), resp.text.index('id="safe-btn"')
        )

    def test_safe_and_sos_actions_start_disabled(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        # Both buttons must be non-actionable until location is acquired.
        safe_tag_start = resp.text.index('id="safe-btn"')
        safe_tag = resp.text[max(0, safe_tag_start - 40): safe_tag_start + 60]
        sos_tag_start = resp.text.index('id="sos-btn"')
        sos_tag = resp.text[max(0, sos_tag_start - 40): sos_tag_start + 60]
        self.assertIn("disabled", safe_tag)
        self.assertIn("disabled", sos_tag)

    def test_sos_button_present_for_submission(self):
        # Phase S4 wires SOS to a real server-side submission endpoint --
        # see tests/test_safety_checkin_submission_s4.py -- so this only
        # checks the button itself is still present and correctly labeled.
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertIn('id="sos-btn"', resp.text)

    def test_geolocation_status_element_present(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertIn('id="location-status"', resp.text)

    def test_geolocation_api_usage_present(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertIn("navigator.geolocation", resp.text)
        self.assertIn("getCurrentPosition", resp.text)

    def test_geolocation_error_paths_all_handled(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        # requesting / acquired / denied / unavailable / timeout states.
        self.assertIn("PERMISSION_DENIED", resp.text)
        self.assertIn("POSITION_UNAVAILABLE", resp.text)
        self.assertIn("TIMEOUT", resp.text)
        self.assertIn("'geolocation' in navigator", resp.text)

    def test_no_fake_or_fallback_coordinates(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        lowered = resp.text.lower()
        self.assertNotIn("ip geolocation", lowered)
        self.assertNotIn("ipapi", lowered)
        self.assertNotIn("ipgeolocation", lowered)

    # ── S2 regressions preserved ────────────────────────────────────────

    def test_unknown_token_returns_404(self):
        resp = self.client.get("/safety/c/does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_inactive_token_returns_identical_404(self):
        active_missing_resp = self.client.get("/safety/c/does-not-exist")
        user = self._make_user(nfc_token="nfc-inactive", is_active=False)
        inactive_resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(inactive_resp.status_code, 404)
        self.assertEqual(inactive_resp.json(), active_missing_resp.json())

    def test_get_causes_no_safety_db_mutation(self):
        user = self._make_user()
        self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)
        self.assertEqual(self.db.query(models.SafetyAlert).count(), 0)
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 0)

    def test_display_name_is_html_escaped(self):
        user = self._make_user(
            nfc_token="nfc-xss", display_name="<script>alert(1)</script>"
        )
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("<script>alert(1)</script>", resp.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", resp.text)


if __name__ == "__main__":
    unittest.main()
