"""Regression tests for Safety Engine v1 Phase S4 (Secure Check-in / SOS
Submission — POST /safety/c/{secure_token}/check-in and
POST /safety/c/{secure_token}/sos).

Mirrors the S2/S3 test harness: a minimal FastAPI app registers only the
safety_public routes with get_db overridden to an isolated in-memory SQLite
database. Never imports main.py.
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
from safety_public import (
    SafetyCheckInResponse,
    SafetyGPSPayload,
    SafetySOSResponse,
    serve_safety_entry,
    submit_check_in,
    submit_sos,
)


class SafetyCheckInSubmissionS4Tests(unittest.TestCase):
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

        @app.post("/safety/c/{secure_token}/check-in", response_model=SafetyCheckInResponse)
        def safety_check_in(secure_token: str, payload: SafetyGPSPayload, db=Depends(get_db)):
            return submit_check_in(secure_token, payload, db)

        @app.post("/safety/c/{secure_token}/sos", response_model=SafetySOSResponse)
        def safety_sos(secure_token: str, payload: SafetyGPSPayload, db=Depends(get_db)):
            return submit_sos(secure_token, payload, db)

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

    VALID_GPS = {"latitude": 40.7128, "longitude": -74.0060, "accuracy": 12.5}

    # ── I'M SAFE — success ──────────────────────────────────────────────

    def test_check_in_success_returns_200_and_persists_row(self):
        user = self._make_user()
        resp = self.client.post(f"/safety/c/{user.secure_token}/check-in", json=self.VALID_GPS)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

        rows = self.db.query(models.SafetyCheckIn).all()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.user_id, user.id)
        self.assertEqual(row.latitude, self.VALID_GPS["latitude"])
        self.assertEqual(row.longitude, self.VALID_GPS["longitude"])
        self.assertEqual(row.accuracy_m, self.VALID_GPS["accuracy"])
        self.assertEqual(row.source, "public_web")
        self.assertIsNotNone(row.checked_in_at)

    def test_check_in_without_accuracy_is_accepted_and_nullable(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in",
            json={"latitude": 1.0, "longitude": 2.0},
        )
        self.assertEqual(resp.status_code, 200)
        row = self.db.query(models.SafetyCheckIn).first()
        self.assertIsNone(row.accuracy_m)

    def test_check_in_ignores_client_supplied_user_id_and_timestamp(self):
        user = self._make_user()
        other_user = self._make_user(nfc_token="nfc-2", display_name="Bob")
        payload = dict(self.VALID_GPS)
        payload["user_id"] = other_user.id
        payload["checked_in_at"] = "2000-01-01T00:00:00Z"
        resp = self.client.post(f"/safety/c/{user.secure_token}/check-in", json=payload)
        self.assertEqual(resp.status_code, 200)
        row = self.db.query(models.SafetyCheckIn).first()
        self.assertEqual(row.user_id, user.id)
        self.assertNotEqual(row.checked_in_at.year, 2000)

    def test_check_in_response_does_not_leak_internal_ids(self):
        user = self._make_user()
        resp = self.client.post(f"/safety/c/{user.secure_token}/check-in", json=self.VALID_GPS)
        body = resp.json()
        self.assertNotIn("id", body)
        self.assertNotIn("user_id", body)

    # ── I'M SAFE — validation / failure ─────────────────────────────────

    def test_check_in_missing_latitude_returns_422_and_no_write(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in", json={"longitude": -74.0}
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_missing_longitude_returns_422_and_no_write(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in", json={"latitude": 40.0}
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_malformed_latitude_type_returns_422(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in",
            json={"latitude": "not-a-number", "longitude": 1.0},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_latitude_out_of_range_returns_422(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in",
            json={"latitude": 91.0, "longitude": 0.0},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_longitude_out_of_range_returns_422(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in",
            json={"latitude": 0.0, "longitude": -181.0},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_negative_accuracy_returns_422(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in",
            json={"latitude": 0.0, "longitude": 0.0, "accuracy": -5.0},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_malformed_accuracy_type_returns_422(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in",
            json={"latitude": 0.0, "longitude": 0.0, "accuracy": "far"},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_malformed_body_returns_422(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_unknown_token_returns_404_and_no_write(self):
        resp = self.client.post("/safety/c/does-not-exist/check-in", json=self.VALID_GPS)
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_inactive_user_returns_identical_404(self):
        unknown_resp = self.client.post("/safety/c/does-not-exist/check-in", json=self.VALID_GPS)
        user = self._make_user(nfc_token="nfc-inactive", is_active=False)
        inactive_resp = self.client.post(
            f"/safety/c/{user.secure_token}/check-in", json=self.VALID_GPS
        )
        self.assertEqual(inactive_resp.status_code, 404)
        self.assertEqual(inactive_resp.json(), unknown_resp.json())
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_repeated_check_in_requests_each_persist_independently(self):
        user = self._make_user()
        for _ in range(3):
            resp = self.client.post(
                f"/safety/c/{user.secure_token}/check-in", json=self.VALID_GPS
            )
            self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 3)

    # ── SOS — success ────────────────────────────────────────────────────

    def test_sos_success_returns_200_and_persists_open_emergency(self):
        user = self._make_user()
        resp = self.client.post(f"/safety/c/{user.secure_token}/sos", json=self.VALID_GPS)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "received"})

        rows = self.db.query(models.SafetyEmergency).all()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row.user_id, user.id)
        self.assertEqual(row.status, "open")
        self.assertEqual(row.latitude, self.VALID_GPS["latitude"])
        self.assertEqual(row.longitude, self.VALID_GPS["longitude"])
        self.assertEqual(row.accuracy_m, self.VALID_GPS["accuracy"])
        self.assertIsNotNone(row.triggered_at)

    def test_sos_ignores_client_supplied_user_id_and_timestamp(self):
        user = self._make_user()
        other_user = self._make_user(nfc_token="nfc-2", display_name="Bob")
        payload = dict(self.VALID_GPS)
        payload["user_id"] = other_user.id
        payload["triggered_at"] = "2000-01-01T00:00:00Z"
        resp = self.client.post(f"/safety/c/{user.secure_token}/sos", json=payload)
        self.assertEqual(resp.status_code, 200)
        row = self.db.query(models.SafetyEmergency).first()
        self.assertEqual(row.user_id, user.id)
        self.assertNotEqual(row.triggered_at.year, 2000)

    def test_sos_response_does_not_leak_internal_ids(self):
        user = self._make_user()
        resp = self.client.post(f"/safety/c/{user.secure_token}/sos", json=self.VALID_GPS)
        body = resp.json()
        self.assertNotIn("id", body)
        self.assertNotIn("user_id", body)

    # ── SOS — validation / failure ──────────────────────────────────────

    def test_sos_missing_gps_returns_422_and_no_write(self):
        user = self._make_user()
        resp = self.client.post(f"/safety/c/{user.secure_token}/sos", json={})
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 0)

    def test_sos_out_of_range_coordinates_returns_422_and_no_write(self):
        user = self._make_user()
        resp = self.client.post(
            f"/safety/c/{user.secure_token}/sos",
            json={"latitude": 200.0, "longitude": 0.0},
        )
        self.assertEqual(resp.status_code, 422)
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 0)

    def test_sos_unknown_token_returns_404_and_no_write(self):
        resp = self.client.post("/safety/c/does-not-exist/sos", json=self.VALID_GPS)
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 0)

    def test_sos_inactive_user_returns_identical_404(self):
        unknown_resp = self.client.post("/safety/c/does-not-exist/sos", json=self.VALID_GPS)
        user = self._make_user(nfc_token="nfc-inactive", is_active=False)
        inactive_resp = self.client.post(f"/safety/c/{user.secure_token}/sos", json=self.VALID_GPS)
        self.assertEqual(inactive_resp.status_code, 404)
        self.assertEqual(inactive_resp.json(), unknown_resp.json())
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 0)

    def test_sos_does_not_write_to_check_in_table(self):
        user = self._make_user()
        self.client.post(f"/safety/c/{user.secure_token}/sos", json=self.VALID_GPS)
        self.assertEqual(self.db.query(models.SafetyCheckIn).count(), 0)

    def test_check_in_does_not_write_to_emergency_table(self):
        user = self._make_user()
        self.client.post(f"/safety/c/{user.secure_token}/check-in", json=self.VALID_GPS)
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 0)

    # ── S4 UI regressions ───────────────────────────────────────────────

    def test_ui_no_longer_claims_sos_non_operational(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        lowered = resp.text.lower()
        self.assertNotIn("not yet operational", lowered)
        self.assertNotIn("no alert will be sent", lowered)
        self.assertNotIn("no emergency alert was sent", lowered)

    def test_ui_wires_fetch_submission_for_both_actions(self):
        user = self._make_user()
        resp = self.client.get(f"/safety/c/{user.secure_token}")
        self.assertIn("/check-in", resp.text)
        self.assertIn("/sos", resp.text)
        self.assertIn("fetch(", resp.text)


if __name__ == "__main__":
    unittest.main()
