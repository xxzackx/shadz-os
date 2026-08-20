"""Regression test for Safety Engine Hotfix H1B (Early Reminder User-Facing
Copy).

Covers safety_telegram._format_early_reminder only -- the SafetyUser early
reminder message. Before H1B this led with "{display_name} hasn't checked
in yet today." on one line; H1B drops the name prefix and moves the
deadline onto its own bulleted line. Admin-facing Missed Check-in alerts
(_format_missed_checkin), SOS alerts (_format_sos), and late-checkin notices
(_format_late_checkin) are untouched -- not covered here since their copy
didn't change.
"""
import os
import sys
import unittest
from datetime import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import safety_telegram


class _FakeSafetyUser:
    """Minimal stand-in with just the attributes _format_early_reminder
    reads -- avoids needing a DB session for a pure string-formatting test."""

    def __init__(self, display_name, deadline, timezone_name):
        self.display_name = display_name
        self.daily_deadline = deadline
        self.timezone = timezone_name


class EarlyReminderCopyH1BTests(unittest.TestCase):
    def test_exact_message_format(self):
        user = _FakeSafetyUser("Alice", time(21, 0), "Asia/Phnom_Penh")
        self.assertEqual(
            safety_telegram._format_early_reminder(user),
            "⏰ Reminder: You haven’t checked in yet today.\n"
            "• Daily deadline: 21:00 (Asia/Phnom_Penh).",
        )

    def test_no_display_name_prefix(self):
        user = _FakeSafetyUser("Bob", time(9, 5), "UTC")
        message = safety_telegram._format_early_reminder(user)
        self.assertNotIn("Bob", message)

    def test_reflects_configured_deadline_and_timezone(self):
        user = _FakeSafetyUser("Carol", time(6, 30), "America/New_York")
        message = safety_telegram._format_early_reminder(user)
        self.assertIn("06:30 (America/New_York).", message)


if __name__ == "__main__":
    unittest.main()
