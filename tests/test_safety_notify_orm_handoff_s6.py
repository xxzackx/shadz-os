"""Regression test for the S6 ORM-handoff bug (production
DetachedInstanceError).

main.py's real `_collect_due_safety_notifications()` commits internally
(collect_due_*() claims delivery leases via conditional UPDATE + commit)
and then closes its Session before returning the ORM objects (SafetyUser,
SafetyAlert, SafetyDailyState, SafetyEmergency, SafetyCheckIn,
SafetyLateCheckinAlert) that safety_telegram's message formatters read
afterward, inside main.py's `_deliver_*` helpers.

Phase S6.1 adds collect_due_late_checkin_alerts, which follows the exact
same collect-then-claim-then-refresh shape as collect_due_missed_alerts
(see safety_notify.py) and is collected through the same _SafetyNotifySession
(expire_on_commit=False) as every other S6 collector -- this file audits
that it genuinely obeys the same safe detached-handoff contract as the
already-fixed reminder/missed/sos paths, including in a batch where SOS
(a later collector in main.py's reminders -> missed -> late_checkins -> sos
order) is collected right after it.
With database.py's app-wide SessionLocal (expire_on_commit=True, its
default -- left unchanged by this fix), each intervening commit expires
the already-loaded objects, so any attribute read after the Session
closes raises sqlalchemy.orm.exc.DetachedInstanceError. This is exactly
what production hit: a SafetyAlert got claimed correctly
(delivery_claimed_at set), but the reminder never reached Telegram
because formatting the message required reading user.display_name off an
expired/detached instance, leaving notified_at NULL forever.

The fix is a Session-local sessionmaker (_SafetyNotifySession in main.py)
with expire_on_commit=False, scoped to just
`_collect_due_safety_notifications`. database.py's SessionLocal is
untouched, so every other Session in the app keeps its original
expire-on-commit behavior.

Runs main.py in a subprocess against a throwaway temp SQLite file --
matching this suite's existing rule (see test_safety_public_entry_s2.py)
that no test imports main.py in-process, to avoid touching the real
shadz.db and to avoid one process's module-level engine/Session state
leaking into other tests. This is a real reproduction of the actual
boundary: a Session that has committed at least once, is then closed, and
whose returned ORM objects are read afterward -- a test that keeps its
own Session open the whole time (as safety_notify.py's other unit tests
do) cannot reproduce this. Does not start FastAPI's startup event or the
background notify loop -- a plain module import plus a direct call to the
sync collector helper is enough to exercise the handoff.
"""
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_SCRIPT = textwrap.dedent(
    f"""
    import json
    import sys
    from datetime import datetime, time as dt_time, timedelta, timezone

    sys.path.insert(0, {REPO_ROOT!r})

    import main
    import models
    import safety_telegram
    from database import SessionLocal
    from safety_notify import claim_late_checkin_alert
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.orm.exc import DetachedInstanceError

    result = {{}}

    db = SessionLocal()

    now = datetime.now(timezone.utc)
    # Deadline already passed a couple minutes ago, 0-minute reminder
    # window, so the trigger condition is satisfied on the very first tick
    # (the collector uses datetime.now(timezone.utc) internally, not an
    # injectable clock).
    near_past = (now - timedelta(minutes=2)).time()
    reminder_user = models.SafetyUser(
        display_name="Reminder User", timezone="UTC", daily_deadline=near_past,
        early_reminder_minutes=0, nfc_token="tok-reminder-orm-handoff", is_active=True,
    )
    missed_user = models.SafetyUser(
        display_name="Missed User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-missed-orm-handoff", is_active=True,
    )
    late_checkin_user = models.SafetyUser(
        display_name="Late Checkin User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-late-checkin-orm-handoff", is_active=True,
    )
    sos_user = models.SafetyUser(
        display_name="SOS User", timezone="UTC", daily_deadline=dt_time(21, 0),
        early_reminder_minutes=30, nfc_token="tok-sos-orm-handoff", is_active=True,
    )
    db.add_all([reminder_user, missed_user, late_checkin_user, sos_user])
    db.commit()
    db.refresh(reminder_user)
    db.refresh(missed_user)
    db.refresh(late_checkin_user)
    db.refresh(sos_user)
    # Capture plain ids now -- these setup objects go through further
    # commits below (each of which expires them under SessionLocal's
    # default expire_on_commit=True), so their attributes must not be read
    # again after that. Only the *fixed* collector's own returned objects
    # are meant to demonstrate post-close readability.
    reminder_user_id = reminder_user.id
    missed_user_id = missed_user.id
    late_checkin_user_id = late_checkin_user.id
    sos_user_id = sos_user.id

    # Missed check-in: a pre-existing 'missed' SafetyDailyState -- bypasses
    # S5's evaluator entirely, matching how collect_due_missed_alerts reads
    # it (S5's authoritative output, never re-derived here).
    state = models.SafetyDailyState(
        user_id=missed_user_id, safety_date=now.date(), status="missed",
        deadline_utc=now - timedelta(hours=1),
    )
    db.add(state)

    # Late check-in: a real SafetyCheckIn plus the SafetyLateCheckinAlert
    # claim submit_check_in would have made for it (see safety_public.py) --
    # bypasses the HTTP layer entirely, matching how collect_due_late_
    # checkin_alerts only ever reads already-claimed rows, never claims them
    # itself.
    late_checkin = models.SafetyCheckIn(
        user_id=late_checkin_user_id, checked_in_at=now, latitude=3.0, longitude=4.0,
        source="public_web",
    )
    db.add(late_checkin)
    db.flush()
    claim_late_checkin_alert(db, late_checkin_user_id, now.date(), late_checkin.id)

    emergency = models.SafetyEmergency(
        user_id=sos_user_id, latitude=1.0, longitude=2.0, status="open",
    )
    db.add(emergency)
    db.commit()
    db.close()

    reminders, missed, late_checkins, sos = main._collect_due_safety_notifications()

    def find_by_user_id(items, user_id):
        for item in items:
            if item[0].id == user_id:
                return item
        return None

    # ── Early reminder ───────────────────────────────────────────────
    match = find_by_user_id(reminders, reminder_user_id)
    result["reminder_found"] = match is not None
    if match is not None:
        due_user, alert, claim_at = match
        result["reminder_detached"] = sa_inspect(due_user).session is None
        try:
            result["reminder_message"] = safety_telegram._format_early_reminder(due_user)
            result["reminder_ok"] = True
        except DetachedInstanceError:
            result["reminder_ok"] = False
            result["reminder_error"] = "DetachedInstanceError"
        result["reminder_delivery_claimed_at_set"] = alert.delivery_claimed_at is not None
        result["reminder_notified_at_is_none"] = alert.notified_at is None
        result["reminder_claim_at_set"] = claim_at is not None

    # ── Missed check-in alert ────────────────────────────────────────
    match = find_by_user_id(missed, missed_user_id)
    result["missed_found"] = match is not None
    if match is not None:
        due_user, daily_state, alert, claim_at, last_checkin = match
        result["missed_detached"] = (
            sa_inspect(due_user).session is None and sa_inspect(daily_state).session is None
        )
        try:
            result["missed_message"] = safety_telegram._format_missed_checkin(
                due_user, daily_state, last_checkin
            )
            result["missed_ok"] = True
        except DetachedInstanceError:
            result["missed_ok"] = False
            result["missed_error"] = "DetachedInstanceError"
        result["missed_delivery_claimed_at_set"] = alert.delivery_claimed_at is not None
        result["missed_notified_at_is_none"] = alert.notified_at is None

    # ── Late-checkin alert ───────────────────────────────────────────
    match = find_by_user_id(late_checkins, late_checkin_user_id)
    result["late_checkin_found"] = match is not None
    if match is not None:
        due_user, due_checkin, alert, claim_at = match
        result["late_checkin_detached"] = (
            sa_inspect(due_user).session is None
            and sa_inspect(due_checkin).session is None
            and sa_inspect(alert).session is None
        )
        try:
            result["late_checkin_message"] = safety_telegram._format_late_checkin(
                due_user, due_checkin, alert
            )
            result["late_checkin_ok"] = True
        except DetachedInstanceError:
            result["late_checkin_ok"] = False
            result["late_checkin_error"] = "DetachedInstanceError"
        result["late_checkin_delivery_claimed_at_set"] = alert.delivery_claimed_at is not None
        result["late_checkin_notified_at_is_none"] = alert.notified_at is None
        result["late_checkin_claim_at_set"] = claim_at is not None

    # ── SOS notification ─────────────────────────────────────────────
    match = find_by_user_id(sos, sos_user_id)
    result["sos_found"] = match is not None
    if match is not None:
        due_user, due_emergency, claim_at = match
        result["sos_detached"] = (
            sa_inspect(due_user).session is None and sa_inspect(due_emergency).session is None
        )
        try:
            result["sos_message"] = safety_telegram._format_sos(due_user, due_emergency)
            result["sos_ok"] = True
        except DetachedInstanceError:
            result["sos_ok"] = False
            result["sos_error"] = "DetachedInstanceError"
        result["sos_claimed_at_set"] = due_emergency.notification_claimed_at is not None
        result["sos_last_notified_at_is_none"] = due_emergency.last_notified_at is None

    print(json.dumps(result))
    """
)


class SafetyNotifyOrmHandoffTests(unittest.TestCase):
    """Reproduces the actual production ORM-handoff boundary end to end,
    once per notification kind."""

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
        result = subprocess.run(
            [sys.executable, "-c", _SCRIPT],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_early_reminder_readable_after_collector_session_closes(self):
        payload = self._run()
        self.assertTrue(payload["reminder_found"])
        # The Session that produced this object is already closed by the
        # time the collector returns it -- the actual production boundary.
        self.assertTrue(payload["reminder_detached"])
        self.assertTrue(payload.get("reminder_ok"), payload.get("reminder_error"))
        # H1B: the message itself no longer carries display_name, but it
        # still reads other detached attributes (daily_deadline, timezone)
        # off the same instance -- this remains a real detached-read check.
        self.assertRegex(
            payload["reminder_message"],
            r"^⏰ Reminder: You haven.t checked in yet today\.\n"
            r"• Daily deadline: \d{2}:\d{2} \(UTC\)\.$",
        )
        self.assertTrue(payload["reminder_delivery_claimed_at_set"])
        self.assertTrue(payload["reminder_notified_at_is_none"])
        self.assertTrue(payload["reminder_claim_at_set"])

    def test_missed_alert_readable_after_collector_session_closes(self):
        payload = self._run()
        self.assertTrue(payload["missed_found"])
        self.assertTrue(payload["missed_detached"])
        self.assertTrue(payload.get("missed_ok"), payload.get("missed_error"))
        self.assertIn("Missed User", payload["missed_message"])
        self.assertTrue(payload["missed_delivery_claimed_at_set"])
        self.assertTrue(payload["missed_notified_at_is_none"])

    def test_late_checkin_alert_readable_after_collector_session_closes(self):
        payload = self._run()
        self.assertTrue(payload["late_checkin_found"])
        self.assertTrue(payload["late_checkin_detached"])
        self.assertTrue(payload.get("late_checkin_ok"), payload.get("late_checkin_error"))
        self.assertIn("Late Checkin User", payload["late_checkin_message"])
        self.assertTrue(payload["late_checkin_delivery_claimed_at_set"])
        self.assertTrue(payload["late_checkin_notified_at_is_none"])
        self.assertTrue(payload["late_checkin_claim_at_set"])

    def test_sos_readable_after_collector_session_closes(self):
        # sos is collected right after late_checkins in main.py's real
        # order (reminders -> missed -> late_checkins -> sos) -- this
        # proves a later collector's objects survive the handoff too, i.e.
        # the late-checkin collector's mid-loop commits (claiming its
        # delivery lease) never expire/detach anything collected after it.
        payload = self._run()
        self.assertTrue(payload["sos_found"])
        self.assertTrue(payload["sos_detached"])
        self.assertTrue(payload.get("sos_ok"), payload.get("sos_error"))
        self.assertIn("SOS User", payload["sos_message"])
        self.assertIn("maps.google.com", payload["sos_message"])
        self.assertTrue(payload["sos_claimed_at_set"])
        self.assertTrue(payload["sos_last_notified_at_is_none"])


if __name__ == "__main__":
    unittest.main()
