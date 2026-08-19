"""Safety Engine v1 Phase S6 — Telegram Reminder + Missed Alert + SOS
Escalation: the "what is due right now, and did we win the claim for it"
layer.

This module never re-derives deadline/day-state logic — it only reads
SafetyDailyState (S5's sole authority for pending/safe/missed) and
SafetyEmergency (S4's SOS record), and reuses
safety_deadline.get_or_create_daily_state directly rather than forking it.

Delivery-retry correction: claiming a notification slot and successfully
delivering it to Telegram are two separate facts, tracked separately, so a
Telegram failure (or a missing SAFETY_TELEGRAM_CHAT_ID) can never
permanently lose a notification:
  - SafetyAlert existence is the one-shot claim per
    (user_id, safety_date, alert_type) — enforced by the DB unique
    constraint uq_safety_alerts_user_date_type — but SafetyAlert.notified_at
    is what actually marks "delivered". While notified_at IS NULL, the row
    stays eligible for delivery.
  - SafetyEmergency.last_notified_at is written ONLY by mark_sos_notified,
    which the caller invokes only after a confirmed-successful Telegram
    send. A failed send never touches it; only a successful send starts the
    SOS_RETRY_INTERVAL_SECONDS cooldown before the next retry.

Concurrency correction: "eligible for delivery" and "reserved for delivery
by this worker" are ALSO two separate facts. Two independent
collect_due_*() calls (different workers/processes, or two overlapping
ticks) reading the same eligible row would otherwise both return it, both
send Telegram, and only race afterward when marking success — a real
double-send. To prevent that, collect_due_*() never just reads: for every
otherwise-eligible row it also attempts an atomic conditional UPDATE that
sets a short-lived delivery lease (SafetyAlert.delivery_claimed_at /
SafetyEmergency.notification_claimed_at, see DELIVERY_LEASE_SECONDS below)
and only returns the row if THIS call's UPDATE actually matched it — i.e.
this call won the race. A losing call's UPDATE matches zero rows and that
candidate is simply skipped, exactly like the existing
get_or_create_daily_state / SafetyAlert unique-constraint patterns
elsewhere in this codebase.

The lease is intentionally NOT a distributed lock or a queue: it is one
plain nullable timestamp column per table, claimed and released with
ordinary conditional UPDATEs, matching the SQLite single-file, no --workers
deployment this app already runs. Telegram sendMessage can never provide a
true cross-system exactly-once transaction with SQLite, so this optimizes
for *at-least-once* safe delivery: the lease prevents the *normal*
concurrent-double-claim case, and a crash that leaves a lease held is never
fatal -- it simply expires after DELIVERY_LEASE_SECONDS and the row becomes
claimable again on the next tick. Retryability is never sacrificed to chase
impossible crash-proof exactly-once semantics.

Lease-ownership correction: a stale worker whose lease already expired and
was reclaimed by someone else must never be able to release or mark
success for that *new* claim. So collect_due_*() returns the exact
delivery_claimed_at / notification_claimed_at value it just won alongside
each due item, and release_alert_delivery_claim / mark_alert_notified /
release_sos_delivery_claim / mark_sos_notified all require that exact
value to still be the persisted one before they touch anything. A stale
caller's expected value no longer matches (a newer worker's claim, or NULL
after that worker finished), so its UPDATE matches zero rows and is a safe
no-op -- it can never clear or overwrite a lease it no longer actually
holds.

Neither collect_due_* function ever calls out to Telegram itself — they
only read/claim rows. Actually sending, and marking success/releasing the
claim, is the caller's job (see main.py's notify loop + safety_telegram.py),
so a Telegram outcome can never affect SafetyDailyState or SafetyCheckIn
data at all, and a Telegram failure can at most leave a
SafetyAlert/SafetyEmergency row claimed-then-released (or, on a crash,
claimed until the lease expires) — never lose or corrupt it.
"""
from datetime import datetime, timedelta, timezone

import models
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from safety_deadline import get_or_create_daily_state, local_safety_date

# Cadence for repeat SOS notifications while status is 'open' or
# 'acknowledged', counted from the last *successful* delivery (see
# mark_sos_notified). One explicit, named constant instead of scattering
# timing magic through the module.
#
# Phase S7: escalation eligibility is status IN ('open', 'acknowledged') —
# acknowledging an SOS (see acknowledge_sos below) deliberately does NOT stop
# escalation on its own, only resolving it does (status == 'resolved'). See
# _SOS_ESCALATION_STATUSES.
SOS_RETRY_INTERVAL_SECONDS = 300

# Phase S7 — SafetyEmergency statuses for which SOS escalation stays active.
# 'resolved' is the only status that stops it; 'acknowledged' alone must not
# (an admin acknowledging an SOS is not the same as the situation being
# resolved — see models.SafetyEmergency and safety_admin.py's
# acknowledge/resolve routes).
_SOS_ESCALATION_STATUSES = ("open", "acknowledged")

# How long a delivery claim (SafetyAlert.delivery_claimed_at /
# SafetyEmergency.notification_claimed_at) is honored before it's treated as
# abandoned and the row becomes claimable again. One explicit, named
# constant covering both lease types -- comfortably longer than a single
# Telegram HTTP attempt (safety_telegram uses a 10s httpx timeout) so a
# slow-but-healthy send is never preempted by another worker, while still
# short enough that a crashed worker's claim self-heals well within one
# notify-loop interval.
DELIVERY_LEASE_SECONDS = 90


def _as_aware_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _get_or_create_alert(
    db: Session, user_id: int, safety_date, alert_type: str
) -> "models.SafetyAlert":
    """Fetch the single logical (user, safety_date, alert_type) SafetyAlert,
    creating it if this is the first tick to observe it due.

    The row's mere existence is the one-shot *claim slot* (never created
    twice — enforced by uq_safety_alerts_user_date_type); whether it has
    actually been delivered yet, and whether some worker currently holds
    the delivery lease for it, are separate questions answered by
    notified_at / delivery_claimed_at (see _claim_alert_delivery). A
    concurrent/duplicate insert race here is absorbed with a SAVEPOINT,
    exactly like safety_deadline.get_or_create_daily_state.
    """
    existing = (
        db.query(models.SafetyAlert)
        .filter(
            models.SafetyAlert.user_id == user_id,
            models.SafetyAlert.safety_date == safety_date,
            models.SafetyAlert.alert_type == alert_type,
        )
        .first()
    )
    if existing is not None:
        return existing

    row = models.SafetyAlert(user_id=user_id, safety_date=safety_date, alert_type=alert_type)
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        return (
            db.query(models.SafetyAlert)
            .filter(
                models.SafetyAlert.user_id == user_id,
                models.SafetyAlert.safety_date == safety_date,
                models.SafetyAlert.alert_type == alert_type,
            )
            .one()
        )
    db.commit()
    return row


def _claim_alert_delivery(db: Session, alert_id: int, now: datetime) -> bool:
    """Atomically reserve alert_id for delivery by this caller, or fail.

    Claimable only when not yet successfully delivered (notified_at IS
    NULL) AND no unexpired lease is held (delivery_claimed_at IS NULL or
    older than DELIVERY_LEASE_SECONDS). The UPDATE re-checks all of that in
    its WHERE clause, so of any number of concurrent callers racing to
    claim the same row, only the one whose UPDATE actually matches (this
    process's DB commit landing first) gets True back -- every other
    caller's UPDATE matches zero rows and must treat this alert as not
    currently due.
    """
    lease_cutoff = now - timedelta(seconds=DELIVERY_LEASE_SECONDS)
    claimed = (
        db.query(models.SafetyAlert)
        .filter(
            models.SafetyAlert.id == alert_id,
            models.SafetyAlert.notified_at.is_(None),
            or_(
                models.SafetyAlert.delivery_claimed_at.is_(None),
                models.SafetyAlert.delivery_claimed_at <= lease_cutoff,
            ),
        )
        .update({"delivery_claimed_at": now}, synchronize_session=False)
    )
    db.commit()
    return bool(claimed)


def release_alert_delivery_claim(
    db: Session, alert_id: int, expected_claimed_at: datetime
) -> bool:
    """Release alert_id's delivery lease -- but ONLY if it is still held by
    the exact claim (delivery_claimed_at == expected_claimed_at) this
    caller originally won from _claim_alert_delivery.

    This is the lease-ownership fix: without the expected_claimed_at check,
    a stale/expired worker calling this after its lease was reclaimed by a
    newer worker would blindly clear delivery_claimed_at = NULL, wiping out
    the *new* owner's lease and letting a third worker double-claim it. By
    requiring the exact previously-won timestamp, a stale caller's UPDATE
    matches zero rows (the column now holds a different value, or NULL if
    the newer owner already finished) and is a safe no-op. Also scoped to
    notified_at IS NULL so this can never clear a lease out from under an
    alert some other path has already marked delivered. Returns True only
    if this call actually cleared its own lease.
    """
    updated = (
        db.query(models.SafetyAlert)
        .filter(
            models.SafetyAlert.id == alert_id,
            models.SafetyAlert.notified_at.is_(None),
            models.SafetyAlert.delivery_claimed_at == expected_claimed_at,
        )
        .update({"delivery_claimed_at": None}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)


def mark_alert_notified(
    db: Session, alert_id: int, now: datetime, expected_claimed_at: datetime
) -> bool:
    """Record a confirmed-successful Telegram delivery for a SafetyAlert
    and release its delivery lease in the same UPDATE -- but ONLY if
    expected_claimed_at still matches delivery_claimed_at, i.e. this caller
    is still the lease's current owner (see release_alert_delivery_claim
    for why that check exists: it stops a stale/expired worker from
    recording success -- or clearing a newer owner's lease -- for a claim
    it no longer actually holds).

    Conditional UPDATE ... WHERE notified_at IS NULL AND
    delivery_claimed_at == expected_claimed_at, so a second caller (a
    duplicate tick, a race, or a stale reclaimed-lease caller) marking the
    same alert is a safe no-op, never a double-send record. Returns True
    only if this call actually transitioned the row.
    """
    updated = (
        db.query(models.SafetyAlert)
        .filter(
            models.SafetyAlert.id == alert_id,
            models.SafetyAlert.notified_at.is_(None),
            models.SafetyAlert.delivery_claimed_at == expected_claimed_at,
        )
        .update({"notified_at": now, "delivery_claimed_at": None}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)


def collect_due_early_reminders(
    db: Session, now: datetime
) -> list[tuple["models.SafetyUser", "models.SafetyAlert", datetime]]:
    """Return (user, alert, claim_at) for every early-reminder alert this
    call just won the delivery lease for.

    claim_at is the exact delivery_claimed_at value now persisted on the
    row (re-read via db.refresh after the winning claim, not just the `now`
    passed in -- SQLite may round-trip a timestamp with reduced precision,
    so the caller must hold the actual stored value to prove lease
    ownership later). The caller (main.py) must thread this exact value
    into mark_alert_notified / release_alert_delivery_claim so only the
    worker that currently holds the lease can act on it.

    Otherwise-eligible day = active user's current local safety day is
    still pending and now >= deadline_utc - early_reminder_minutes. A day
    that is no longer pending (already safe or missed) is skipped —
    reminders only ever fire for a still-pending day. A row that already
    exists from an earlier tick but failed to deliver (lease released, or
    expired after a crash) is claimable and returned again here.
    """
    due: list[tuple[models.SafetyUser, models.SafetyAlert, datetime]] = []
    users = db.query(models.SafetyUser).filter(models.SafetyUser.is_active.is_(True)).all()
    for user in users:
        today = local_safety_date(user, now)
        row = get_or_create_daily_state(db, user, today)
        if row.status != "pending":
            continue
        trigger_at = _as_aware_utc(row.deadline_utc) - timedelta(minutes=user.early_reminder_minutes)
        if now < trigger_at:
            continue
        alert = _get_or_create_alert(db, user.id, today, "early_reminder")
        if alert.notified_at is not None:
            continue
        if _claim_alert_delivery(db, alert.id, now):
            db.refresh(alert)
            due.append((user, alert, alert.delivery_claimed_at))
    return due


def collect_due_missed_alerts(
    db: Session, now: datetime
) -> list[tuple["models.SafetyUser", "models.SafetyDailyState", "models.SafetyAlert", datetime]]:
    """Return (user, daily_state, alert, claim_at) for every missed-checkin
    alert this call just won the delivery lease for.

    claim_at is the exact delivery_claimed_at value now persisted on the
    row (see collect_due_early_reminders for why it's re-read rather than
    reusing `now`) -- the caller must thread it into mark_alert_notified /
    release_alert_delivery_claim to prove it still owns the lease.

    Scans across every missed day (not just "today"), so a backlog built
    up during downtime still gets delivered once S5 evaluation catches up.
    A row that already exists but failed to deliver is claimable and
    returned again here.
    """
    due: list[tuple[models.SafetyUser, models.SafetyDailyState, models.SafetyAlert, datetime]] = []
    rows = (
        db.query(models.SafetyDailyState, models.SafetyUser)
        .join(models.SafetyUser, models.SafetyUser.id == models.SafetyDailyState.user_id)
        .filter(
            models.SafetyDailyState.status == "missed",
            models.SafetyUser.is_active.is_(True),
        )
        .all()
    )
    for row, user in rows:
        alert = _get_or_create_alert(db, user.id, row.safety_date, "missed_checkin")
        # Phase S7: a resolved missed-checkin alert (see
        # resolve_missed_checkin_alert) must never be re-collected or
        # re-sent, even if it was resolved before ever being delivered.
        if alert.status == "resolved" or alert.notified_at is not None:
            continue
        if _claim_alert_delivery(db, alert.id, now):
            db.refresh(alert)
            due.append((user, row, alert, alert.delivery_claimed_at))
    return due


def _get_or_create_missed_alert_no_commit(
    db: Session, user_id: int, safety_date
) -> "models.SafetyAlert":
    """Same fetch-or-create-with-savepoint shape as _get_or_create_alert,
    but only flushes, never commits -- for use from safety_public.submit_
    check_in (Phase S7), which owns its own transaction boundary and must
    not have it prematurely committed here (unlike _get_or_create_alert's
    callers, which are top-level notify-loop entry points that already
    commit independently)."""
    existing = (
        db.query(models.SafetyAlert)
        .filter(
            models.SafetyAlert.user_id == user_id,
            models.SafetyAlert.safety_date == safety_date,
            models.SafetyAlert.alert_type == "missed_checkin",
        )
        .first()
    )
    if existing is not None:
        return existing

    row = models.SafetyAlert(user_id=user_id, safety_date=safety_date, alert_type="missed_checkin")
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        return (
            db.query(models.SafetyAlert)
            .filter(
                models.SafetyAlert.user_id == user_id,
                models.SafetyAlert.safety_date == safety_date,
                models.SafetyAlert.alert_type == "missed_checkin",
            )
            .one()
        )
    return row


def resolve_missed_checkin_alert(
    db: Session, user_id: int, safety_date, checkin_id: int
) -> "models.SafetyAlert":
    """Phase S7 — resolve the missed-checkin SafetyAlert for (user_id,
    safety_date), the moment a later valid check-in for that exact user and
    day arrives (see safety_public.submit_check_in, called under the same
    "late check-in" condition as claim_late_checkin_alert).

    Reuses SafetyAlert's existing status / resolved_at / resolved_checkin_id
    columns (present since the table's Phase S6 creation, unused until now)
    rather than a parallel alert/resolution system. This never touches
    SafetyDailyState -- S5's MISSED-is-terminal rule for the *daily state*
    itself is unchanged; only the operational "should Admin still be told /
    keep being told about this missed check-in" alert is affected.

    Pre-creates the alert (already resolved) via
    _get_or_create_missed_alert_no_commit when it doesn't exist yet -- this
    covers the race where a late check-in arrives before the periodic
    evaluator (safety_deadline.evaluate_user_deadline) has flipped the day's
    SafetyDailyState to 'missed' and so no SafetyAlert row exists yet: by
    resolving it up front, the alert can never later be created "open" and
    sent to Admin for a day that already has a valid (if late) check-in.

    Idempotent: the transition is a conditional UPDATE ... WHERE
    status = 'open', so a second/duplicate late check-in the same day (or a
    race with the notify loop) never re-resolves or overwrites an
    already-resolved alert's resolved_at / resolved_checkin_id.

    Only flushes, never commits -- joins the caller's (submit_check_in's)
    existing atomic transaction, exactly like claim_late_checkin_alert.
    Scoped strictly to the given user_id/safety_date, so one user's check-in
    can never resolve another user's (or another day's) alert.
    """
    alert = _get_or_create_missed_alert_no_commit(db, user_id, safety_date)
    if alert.status == "resolved":
        return alert
    db.query(models.SafetyAlert).filter(
        models.SafetyAlert.id == alert.id,
        models.SafetyAlert.status == "open",
    ).update(
        {
            "status": "resolved",
            "resolved_at": datetime.now(timezone.utc),
            "resolved_checkin_id": checkin_id,
        },
        synchronize_session=False,
    )
    db.flush()
    db.refresh(alert)
    return alert


def last_checkin_before(
    db: Session, user_id: int, before: datetime
) -> "models.SafetyCheckIn | None":
    """The most recent SafetyCheckIn for user_id strictly before `before`,
    or None. Used to surface "last known check-in/location" on a missed
    alert — never fabricated, only ever a real persisted row."""
    return (
        db.query(models.SafetyCheckIn)
        .filter(
            models.SafetyCheckIn.user_id == user_id,
            models.SafetyCheckIn.checked_in_at < before,
        )
        .order_by(models.SafetyCheckIn.checked_in_at.desc())
        .first()
    )


def claim_late_checkin_alert(
    db: Session, user_id: int, safety_date, checkin_id: int
) -> "models.SafetyLateCheckinAlert":
    """Phase S6.1 — record that a late check-in happened for (user_id,
    safety_date), creating the one-shot claim row if this is the first late
    check-in observed for that day (see models.SafetyLateCheckinAlert).

    Called synchronously from safety_public.submit_check_in once it has
    determined the check-in is late -- this only ever claims/records the
    event; delivering the Admin Telegram notification is still the async
    notify loop's job (collect_due_late_checkin_alerts below), exactly like
    every other S6 notification. A second late check-in the same day is a
    safe no-op here (the unique constraint keeps exactly one row), so the
    caller's checkin_id argument is only used the first time.

    Only flushes, never commits -- submit_check_in owns the transaction
    boundary, exactly like safety_deadline.resolve_checkin, so the
    SafetyCheckIn insert, any SafetyDailyState change, and this claim all
    commit (or roll back) together as one atomic unit. The uq_safety_late_
    checkin_alerts_user_date unique constraint is still the real one-shot
    guarantee, enforced at flush time inside the SAVEPOINT below -- it does
    not depend on this function committing.
    """
    existing = (
        db.query(models.SafetyLateCheckinAlert)
        .filter(
            models.SafetyLateCheckinAlert.user_id == user_id,
            models.SafetyLateCheckinAlert.safety_date == safety_date,
        )
        .first()
    )
    if existing is not None:
        return existing

    row = models.SafetyLateCheckinAlert(
        user_id=user_id, safety_date=safety_date, checkin_id=checkin_id
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        return (
            db.query(models.SafetyLateCheckinAlert)
            .filter(
                models.SafetyLateCheckinAlert.user_id == user_id,
                models.SafetyLateCheckinAlert.safety_date == safety_date,
            )
            .one()
        )
    return row


def _claim_late_checkin_delivery(db: Session, alert_id: int, now: datetime) -> bool:
    """Atomically reserve a SafetyLateCheckinAlert for delivery -- same
    claimable-when-undelivered-and-unleased contract as
    _claim_alert_delivery."""
    lease_cutoff = now - timedelta(seconds=DELIVERY_LEASE_SECONDS)
    claimed = (
        db.query(models.SafetyLateCheckinAlert)
        .filter(
            models.SafetyLateCheckinAlert.id == alert_id,
            models.SafetyLateCheckinAlert.notified_at.is_(None),
            or_(
                models.SafetyLateCheckinAlert.delivery_claimed_at.is_(None),
                models.SafetyLateCheckinAlert.delivery_claimed_at <= lease_cutoff,
            ),
        )
        .update({"delivery_claimed_at": now}, synchronize_session=False)
    )
    db.commit()
    return bool(claimed)


def release_late_checkin_delivery_claim(
    db: Session, alert_id: int, expected_claimed_at: datetime
) -> bool:
    """Release a SafetyLateCheckinAlert's delivery lease after a failed
    send -- same lease-ownership contract as release_alert_delivery_claim."""
    updated = (
        db.query(models.SafetyLateCheckinAlert)
        .filter(
            models.SafetyLateCheckinAlert.id == alert_id,
            models.SafetyLateCheckinAlert.notified_at.is_(None),
            models.SafetyLateCheckinAlert.delivery_claimed_at == expected_claimed_at,
        )
        .update({"delivery_claimed_at": None}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)


def mark_late_checkin_notified(
    db: Session, alert_id: int, now: datetime, expected_claimed_at: datetime
) -> bool:
    """Record a confirmed-successful late-checkin Telegram delivery -- same
    lease-ownership contract as mark_alert_notified."""
    updated = (
        db.query(models.SafetyLateCheckinAlert)
        .filter(
            models.SafetyLateCheckinAlert.id == alert_id,
            models.SafetyLateCheckinAlert.notified_at.is_(None),
            models.SafetyLateCheckinAlert.delivery_claimed_at == expected_claimed_at,
        )
        .update({"notified_at": now, "delivery_claimed_at": None}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)


def collect_due_late_checkin_alerts(
    db: Session, now: datetime
) -> list[tuple["models.SafetyUser", "models.SafetyCheckIn", "models.SafetyLateCheckinAlert", datetime]]:
    """Return (user, checkin, alert, claim_at) for every late-checkin alert
    this call just won the delivery lease for -- same shape/contract as
    collect_due_missed_alerts. Scoped to is_active users, matching every
    other S6 collector."""
    due: list[tuple[models.SafetyUser, models.SafetyCheckIn, models.SafetyLateCheckinAlert, datetime]] = []
    rows = (
        db.query(models.SafetyLateCheckinAlert, models.SafetyUser)
        .join(models.SafetyUser, models.SafetyUser.id == models.SafetyLateCheckinAlert.user_id)
        .filter(
            models.SafetyLateCheckinAlert.notified_at.is_(None),
            models.SafetyUser.is_active.is_(True),
        )
        .all()
    )
    for alert, user in rows:
        if not _claim_late_checkin_delivery(db, alert.id, now):
            continue
        db.refresh(alert)
        checkin = (
            db.query(models.SafetyCheckIn)
            .filter(models.SafetyCheckIn.id == alert.checkin_id)
            .first()
        )
        if checkin is not None:
            due.append((user, checkin, alert, alert.delivery_claimed_at))
        else:
            # Should never happen (checkin_id is a required FK) -- release
            # rather than leave an unreleasable lease if it somehow does.
            release_late_checkin_delivery_claim(db, alert.id, alert.delivery_claimed_at)
    return due


def _claim_sos_delivery(db: Session, emergency_id: int, now: datetime) -> bool:
    """Atomically reserve emergency_id for SOS notification by this caller.

    Claimable only when still open, due (never successfully notified, or
    SOS_RETRY_INTERVAL_SECONDS elapsed since the last successful one), AND
    no unexpired delivery lease is held. Same win-exactly-once contract as
    _claim_alert_delivery.
    """
    cutoff = now - timedelta(seconds=SOS_RETRY_INTERVAL_SECONDS)
    lease_cutoff = now - timedelta(seconds=DELIVERY_LEASE_SECONDS)
    claimed = (
        db.query(models.SafetyEmergency)
        .filter(
            models.SafetyEmergency.id == emergency_id,
            models.SafetyEmergency.status.in_(_SOS_ESCALATION_STATUSES),
            or_(
                models.SafetyEmergency.last_notified_at.is_(None),
                models.SafetyEmergency.last_notified_at <= cutoff,
            ),
            or_(
                models.SafetyEmergency.notification_claimed_at.is_(None),
                models.SafetyEmergency.notification_claimed_at <= lease_cutoff,
            ),
        )
        .update({"notification_claimed_at": now}, synchronize_session=False)
    )
    db.commit()
    return bool(claimed)


def release_sos_delivery_claim(
    db: Session, emergency_id: int, expected_claimed_at: datetime
) -> bool:
    """Release emergency_id's SOS delivery lease after a failed send -- but
    ONLY if it is still held by the exact claim
    (notification_claimed_at == expected_claimed_at) this caller originally
    won from _claim_sos_delivery.

    Same lease-ownership fix as release_alert_delivery_claim: without the
    expected_claimed_at check, a stale/expired worker could clear a newer
    worker's reclaimed lease out from under it. Returns True only if this
    call actually cleared its own lease.
    """
    updated = (
        db.query(models.SafetyEmergency)
        .filter(
            models.SafetyEmergency.id == emergency_id,
            models.SafetyEmergency.notification_claimed_at == expected_claimed_at,
        )
        .update({"notification_claimed_at": None}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)


def collect_due_sos_notifications(
    db: Session, now: datetime
) -> list[tuple["models.SafetyUser", "models.SafetyEmergency", datetime]]:
    """Return (user, emergency, claim_at) for every open SafetyEmergency
    this call just won the delivery lease for.

    claim_at is the exact notification_claimed_at value now persisted on
    the row (re-read via db.refresh after the winning claim) -- the caller
    must thread it into mark_sos_notified / release_sos_delivery_claim to
    prove it still owns the lease.

    Due = never *successfully* notified yet (last_notified_at IS NULL — the
    initial, immediate notification, including after any number of failed
    attempts) or SOS_RETRY_INTERVAL_SECONDS have elapsed since the last
    successful one. A candidate is only returned if _claim_sos_delivery
    actually won the lease for it — a losing/concurrent caller sees it
    skipped, never double-selected.
    """
    due: list[tuple[models.SafetyUser, models.SafetyEmergency, datetime]] = []
    cutoff = now - timedelta(seconds=SOS_RETRY_INTERVAL_SECONDS)
    lease_cutoff = now - timedelta(seconds=DELIVERY_LEASE_SECONDS)
    candidates = (
        db.query(models.SafetyEmergency)
        .filter(
            models.SafetyEmergency.status.in_(_SOS_ESCALATION_STATUSES),
            or_(
                models.SafetyEmergency.last_notified_at.is_(None),
                models.SafetyEmergency.last_notified_at <= cutoff,
            ),
            or_(
                models.SafetyEmergency.notification_claimed_at.is_(None),
                models.SafetyEmergency.notification_claimed_at <= lease_cutoff,
            ),
        )
        .all()
    )
    for emergency in candidates:
        if not _claim_sos_delivery(db, emergency.id, now):
            continue
        db.refresh(emergency)
        user = db.query(models.SafetyUser).filter(models.SafetyUser.id == emergency.user_id).first()
        if user is not None:
            due.append((user, emergency, emergency.notification_claimed_at))
    return due


def mark_sos_notified(
    db: Session, emergency_id: int, now: datetime, expected_claimed_at: datetime
) -> bool:
    """Record a confirmed-successful SOS Telegram delivery and release its
    delivery lease in the same UPDATE -- but ONLY if expected_claimed_at
    still matches notification_claimed_at, i.e. this caller is still the
    lease's current owner (see release_sos_delivery_claim for why that
    check exists).

    Conditional UPDATE ... WHERE status IN ('open', 'acknowledged') AND
    notification_claimed_at == expected_claimed_at, so this can never
    resurrect/mark an emergency that has since been resolved (S7) -- but,
    deliberately, an *acknowledged* emergency still counts, since
    acknowledgement alone must not stop escalation (see
    _SOS_ESCALATION_STATUSES). This never overwrites across a race with
    another successful send for the same row, and never lets a
    stale/expired-lease caller record success for a claim it no longer
    holds. Returns True only if this call actually transitioned the row --
    the caller must only call this after confirming the Telegram send
    succeeded, never speculatively.
    """
    updated = (
        db.query(models.SafetyEmergency)
        .filter(
            models.SafetyEmergency.id == emergency_id,
            models.SafetyEmergency.status.in_(_SOS_ESCALATION_STATUSES),
            models.SafetyEmergency.notification_claimed_at == expected_claimed_at,
        )
        .update({"last_notified_at": now, "notification_claimed_at": None}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)


def acknowledge_sos(db: Session, emergency_id: int, now: datetime) -> "models.SafetyEmergency | None":
    """Phase S7 — SHADZ Admin acknowledges an open SOS: active -> acknowledged.

    Conditional UPDATE ... WHERE status = 'open', so this only ever
    transitions a still-open emergency; calling it again (or after the
    emergency has already been resolved) is a safe no-op that leaves
    acknowledged_at/status untouched -- repeated acknowledge is always safe,
    and acknowledgement can never regress a resolved emergency back to
    acknowledged. Deliberately does NOT touch SOS escalation eligibility
    (see _SOS_ESCALATION_STATUSES) -- acknowledging alone must not stop
    escalation, only resolving does.

    Returns the current row (whether or not this call changed it), or None
    if emergency_id does not exist at all -- the caller (safety_admin.py)
    treats that as 404.
    """
    db.query(models.SafetyEmergency).filter(
        models.SafetyEmergency.id == emergency_id,
        models.SafetyEmergency.status == "open",
    ).update({"status": "acknowledged", "acknowledged_at": now}, synchronize_session=False)
    db.commit()
    return db.query(models.SafetyEmergency).filter(models.SafetyEmergency.id == emergency_id).first()


def resolve_sos(db: Session, emergency_id: int, now: datetime) -> "models.SafetyEmergency | None":
    """Phase S7 — SHADZ Admin resolves an SOS: acknowledged -> resolved.

    The locked S7 lifecycle is strictly open -> acknowledged -> resolved --
    a still-open SOS must be acknowledged first, so this only transitions a
    currently 'acknowledged' emergency. Conditional UPDATE ... WHERE
    status = 'acknowledged', so:
      - an already-resolved emergency is a safe no-op (repeated resolve is
        always safe, resolved_at is never overwritten by a second call);
      - a still-'open' emergency is left completely untouched -- the caller
        (safety_admin.py) inspects the returned row's status and rejects an
        'open' row with 409 Conflict, since 'open' -> 'resolved' directly is
        not a valid transition.
    Once status becomes 'resolved', every SOS escalation query in this
    module (_SOS_ESCALATION_STATUSES) stops selecting this emergency, so
    escalation stops here and only here.

    Returns the current row (whether or not this call changed it), or None
    if emergency_id does not exist at all -- the caller (safety_admin.py)
    treats that as 404.
    """
    db.query(models.SafetyEmergency).filter(
        models.SafetyEmergency.id == emergency_id,
        models.SafetyEmergency.status == "acknowledged",
    ).update({"status": "resolved", "resolved_at": now}, synchronize_session=False)
    db.commit()
    return db.query(models.SafetyEmergency).filter(models.SafetyEmergency.id == emergency_id).first()
