"""Regression tests for Safety Engine v1 Phase S1 (Foundation & Data Model).

Covers the SafetyUser, SafetyCheckIn, SafetyAlert, and SafetyEmergency models
(defaults, constraints, nullable fields, FKs). Uses an isolated in-memory
SQLite database — never touches the real shadz.db. No routes, no runtime
behavior exist yet in this phase; this file verifies schema shape only.
"""
import os
import sys
import unittest
from datetime import datetime, date, time, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

import models
from database import Base


class SafetyEngineFoundationTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:", connect_args={"check_same_thread": False}
        )
        Base.metadata.create_all(bind=self.engine)
        SessionLocal = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    def _make_user(self, nfc_token="tok-1", early_reminder_minutes=30):
        user = models.SafetyUser(
            display_name="Alice",
            timezone="America/New_York",
            daily_deadline=time(21, 0),
            early_reminder_minutes=early_reminder_minutes,
            nfc_token=nfc_token,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    # ── Tables exist ────────────────────────────────────────────────────

    def test_all_four_tables_created(self):
        for table in (
            "safety_users",
            "safety_check_ins",
            "safety_alerts",
            "safety_emergencies",
        ):
            self.assertIn(table, Base.metadata.tables)

    def test_safety_user_required_columns_exist(self):
        cols = {c.name for c in Base.metadata.tables["safety_users"].columns}
        for expected in (
            "id", "display_name", "timezone", "daily_deadline",
            "early_reminder_minutes", "is_active", "nfc_token",
            "created_at", "updated_at",
        ):
            self.assertIn(expected, cols)

    def test_safety_check_in_required_columns_exist(self):
        cols = {c.name for c in Base.metadata.tables["safety_check_ins"].columns}
        for expected in (
            "id", "user_id", "checked_in_at", "latitude", "longitude",
            "accuracy_m", "source", "created_at",
        ):
            self.assertIn(expected, cols)

    def test_safety_alert_required_columns_exist(self):
        cols = {c.name for c in Base.metadata.tables["safety_alerts"].columns}
        for expected in (
            "id", "user_id", "safety_date", "alert_type", "status",
            "triggered_at", "telegram_message_id", "resolved_at",
            "resolved_checkin_id", "created_at",
        ):
            self.assertIn(expected, cols)

    def test_safety_emergency_required_columns_exist(self):
        cols = {c.name for c in Base.metadata.tables["safety_emergencies"].columns}
        for expected in (
            "id", "user_id", "triggered_at", "latitude", "longitude",
            "accuracy_m", "status", "acknowledged_at", "resolved_at",
            "telegram_message_id",
        ):
            self.assertIn(expected, cols)

    # ── FK definitions present ─────────────────────────────────────────

    def test_check_in_user_id_fk_defined(self):
        fks = Base.metadata.tables["safety_check_ins"].c.user_id.foreign_keys
        self.assertTrue(any(fk.target_fullname == "safety_users.id" for fk in fks))

    def test_alert_user_id_fk_defined(self):
        fks = Base.metadata.tables["safety_alerts"].c.user_id.foreign_keys
        self.assertTrue(any(fk.target_fullname == "safety_users.id" for fk in fks))

    def test_alert_resolved_checkin_id_fk_defined(self):
        fks = Base.metadata.tables["safety_alerts"].c.resolved_checkin_id.foreign_keys
        self.assertTrue(any(fk.target_fullname == "safety_check_ins.id" for fk in fks))

    def test_emergency_user_id_fk_defined(self):
        fks = Base.metadata.tables["safety_emergencies"].c.user_id.foreign_keys
        self.assertTrue(any(fk.target_fullname == "safety_users.id" for fk in fks))

    # ── Defaults ────────────────────────────────────────────────────────

    def test_safety_user_is_active_default_true(self):
        user = self._make_user()
        self.assertTrue(user.is_active)

    def test_safety_alert_status_default_open(self):
        user = self._make_user()
        alert = models.SafetyAlert(
            user_id=user.id,
            safety_date=date(2026, 8, 18),
            alert_type="missed_checkin",
        )
        self.db.add(alert)
        self.db.commit()
        self.db.refresh(alert)
        self.assertEqual(alert.status, "open")

    def test_safety_emergency_status_default_open(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id)
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)
        self.assertEqual(emergency.status, "open")

    # ── nfc_token uniqueness ───────────────────────────────────────────

    def test_nfc_token_uniqueness_enforced(self):
        self._make_user(nfc_token="dup-token")
        dupe = models.SafetyUser(
            display_name="Bob",
            timezone="America/New_York",
            daily_deadline=time(21, 0),
            early_reminder_minutes=30,
            nfc_token="dup-token",
        )
        self.db.add(dupe)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    # ── alert_type / status constraints ────────────────────────────────

    def test_alert_type_allowed_values_accepted(self):
        user = self._make_user()
        for alert_type in ("early_reminder", "missed_checkin"):
            alert = models.SafetyAlert(
                user_id=user.id, safety_date=date(2026, 8, 18), alert_type=alert_type
            )
            self.db.add(alert)
            self.db.commit()
        self.assertEqual(
            self.db.query(models.SafetyAlert).count(), 2
        )

    def test_alert_type_invalid_value_rejected(self):
        user = self._make_user()
        alert = models.SafetyAlert(
            user_id=user.id, safety_date=date(2026, 8, 18), alert_type="bogus"
        )
        self.db.add(alert)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    def test_alert_status_allowed_values_accepted(self):
        user = self._make_user()
        # Distinct safety_date per row -- S6 added a uq_safety_alerts_user_date_type
        # constraint on (user_id, safety_date, alert_type), so same-day/type
        # rows can no longer coexist regardless of status.
        for offset, status in enumerate(("open", "resolved")):
            alert = models.SafetyAlert(
                user_id=user.id,
                safety_date=date(2026, 8, 18 + offset),
                alert_type="missed_checkin",
                status=status,
            )
            self.db.add(alert)
            self.db.commit()
        self.assertEqual(self.db.query(models.SafetyAlert).count(), 2)

    def test_alert_status_invalid_value_rejected(self):
        user = self._make_user()
        alert = models.SafetyAlert(
            user_id=user.id,
            safety_date=date(2026, 8, 18),
            alert_type="missed_checkin",
            status="bogus",
        )
        self.db.add(alert)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    # ── emergency status constraint ────────────────────────────────────

    def test_emergency_status_allowed_values_accepted(self):
        user = self._make_user()
        for status in ("open", "acknowledged", "resolved"):
            emergency = models.SafetyEmergency(user_id=user.id, status=status)
            self.db.add(emergency)
            self.db.commit()
        self.assertEqual(self.db.query(models.SafetyEmergency).count(), 3)

    def test_emergency_status_invalid_value_rejected(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id, status="bogus")
        self.db.add(emergency)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()

    # ── nullable location fields ───────────────────────────────────────

    def test_check_in_location_fields_nullable(self):
        user = self._make_user()
        checkin = models.SafetyCheckIn(user_id=user.id, source="manual")
        self.db.add(checkin)
        self.db.commit()
        self.db.refresh(checkin)
        self.assertIsNone(checkin.latitude)
        self.assertIsNone(checkin.longitude)
        self.assertIsNone(checkin.accuracy_m)

    def test_emergency_location_fields_nullable(self):
        user = self._make_user()
        emergency = models.SafetyEmergency(user_id=user.id)
        self.db.add(emergency)
        self.db.commit()
        self.db.refresh(emergency)
        self.assertIsNone(emergency.latitude)
        self.assertIsNone(emergency.longitude)
        self.assertIsNone(emergency.accuracy_m)

    # ── daily_deadline accepts time values ─────────────────────────────

    def test_daily_deadline_accepts_time_value(self):
        user = self._make_user()
        self.assertEqual(user.daily_deadline, time(21, 0))

    # ── early_reminder_minutes must be supplied ────────────────────────

    def test_early_reminder_minutes_required(self):
        user = models.SafetyUser(
            display_name="Carol",
            timezone="America/New_York",
            daily_deadline=time(21, 0),
            nfc_token="tok-required-test",
        )
        self.db.add(user)
        with self.assertRaises(IntegrityError):
            self.db.commit()
        self.db.rollback()


if __name__ == "__main__":
    unittest.main()
