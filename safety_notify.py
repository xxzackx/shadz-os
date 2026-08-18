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

# Cadence for repeat SOS notifications while status stays 'open', counted
# from the last *successful* delivery (see mark_sos_notified). One explicit,
# named constant instead of scattering timing magic through the module — a
# future S7 acknowledge/resolve workflow stops the escalation simply by
# moving SafetyEmergency.status away from 'open'; nothing here needs to
# change for that.
SOS_RETRY_INTERVAL_SECONDS = 300

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
        if alert.notified_at is not None:
            continue
        if _claim_alert_delivery(db, alert.id, now):
            db.refresh(alert)
            due.append((user, row, alert, alert.delivery_claimed_at))
    return due


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
            models.SafetyEmergency.status == "open",
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
            models.SafetyEmergency.status == "open",
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

    Conditional UPDATE ... WHERE status = 'open' AND
    notification_claimed_at == expected_claimed_at, so this can never
    resurrect/mark an emergency that has since been acknowledged/resolved
    (S7), never overwrites across a race with another successful send for
    the same row, and never lets a stale/expired-lease caller record
    success for a claim it no longer holds. Returns True only if this call
    actually transitioned the row -- the caller must only call this after
    confirming the Telegram send succeeded, never speculatively.
    """
    updated = (
        db.query(models.SafetyEmergency)
        .filter(
            models.SafetyEmergency.id == emergency_id,
            models.SafetyEmergency.status == "open",
            models.SafetyEmergency.notification_claimed_at == expected_claimed_at,
        )
        .update({"last_notified_at": now, "notification_claimed_at": None}, synchronize_session=False)
    )
    db.commit()
    return bool(updated)
