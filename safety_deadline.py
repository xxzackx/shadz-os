"""Safety Engine v1 Phase S5 — Daily Safety State / Deadline Engine.

Owns SafetyDailyState: the persisted, DB-authoritative record of a
SafetyUser's status (pending/safe/missed) for one local safety day.

All day/deadline math is timezone-aware (zoneinfo, using SafetyUser.timezone
— never a hardcoded or server timezone) while every stored timestamp stays
server-authoritative UTC. No in-memory timer is the source of truth: every
function here reads/writes SafetyDailyState directly, so re-running any of
them after a crash, restart, or duplicate trigger converges to the same
result (idempotent, restart-safe, duplicate-safe).

State machine for a single day (S5 scope only):
    PENDING -> SAFE     a SafetyCheckIn with checked_in_at strictly before
                         that day's deadline exists.
    PENDING -> MISSED   the deadline has passed and no such check-in exists.
    MISSED is terminal in S5 — a later check-in never rewrites it back to
    SAFE. Late-check-in resolution is Phase S7's responsibility, not S5's.

Helper functions here (get_or_create_daily_state, the SAFE/MISSED resolution
in resolve_checkin) only flush, never commit — the caller owns the
transaction boundary so a check-in and its daily-state transition commit
(or fail) together as one atomic unit. evaluate_user_deadline and
evaluate_all_active_users do own and commit their transactions, since they
are the top-level entry points for the background trigger.

A failure anywhere in this module (bad timezone, missing data) raises rather
than defaulting to "safe" — fail loud, never fail open on a safety signal.
"""
import logging
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import models
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

logger = logging.getLogger("safety_deadline")

# Bound for the qualifying-check-in lookup window below a day's deadline.
# A local safety day is at most ~25h wide even across DST transitions; 48h
# is a generous, cheap-to-index margin so the lookup never has to scan a
# user's entire check-in history.
_QUALIFYING_CHECKIN_LOOKBACK = timedelta(hours=48)


def _as_aware_utc(dt: datetime) -> datetime:
    """Treat a naive datetime as UTC.

    SQLite does not persist tzinfo on DateTime(timezone=True) columns, so a
    value round-tripped through the DB comes back naive even though it was
    always stored as a UTC instant. Every datetime in this module is UTC by
    convention, so a naive value is simply assumed to already be UTC.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def local_safety_date(user: "models.SafetyUser", at_utc: datetime) -> date:
    """The user's local calendar date for a given UTC instant."""
    return _as_aware_utc(at_utc).astimezone(ZoneInfo(user.timezone)).date()


def local_deadline_utc(user: "models.SafetyUser", safety_date: date) -> datetime:
    """The UTC instant of user's daily_deadline on safety_date, in user.timezone.

    Combining date + time inside ZoneInfo (rather than converting a naive
    UTC guess) makes this correct across DST offset changes. For a wall-clock
    deadline that falls in a DST gap (nonexistent, e.g. 02:30 on a
    spring-forward day) or fold (ambiguous, e.g. 01:30 on a fall-back day),
    Python's zoneinfo resolves it deterministically via PEP 495 `fold`
    semantics (default fold=0 — the pre-transition/standard-offset
    interpretation) rather than raising, so the same (user, safety_date)
    always produces the same UTC instant.
    """
    tz = ZoneInfo(user.timezone)
    local_dt = datetime.combine(safety_date, user.daily_deadline, tzinfo=tz)
    return local_dt.astimezone(timezone.utc)


def get_or_create_daily_state(
    db: Session, user: "models.SafetyUser", safety_date: date
) -> "models.SafetyDailyState":
    """Fetch the SafetyDailyState row for (user, safety_date), creating it if absent.

    Only flushes, never commits — the caller owns the transaction. The
    unique constraint on (user_id, safety_date) is the real integrity
    guarantee; a concurrent-insert race is absorbed with a SAVEPOINT
    (begin_nested) so a losing INSERT only rolls back its own savepoint,
    never anything the caller already flushed/committed in the outer
    transaction.
    """
    existing = (
        db.query(models.SafetyDailyState)
        .filter(
            models.SafetyDailyState.user_id == user.id,
            models.SafetyDailyState.safety_date == safety_date,
        )
        .first()
    )
    if existing is not None:
        return existing

    row = models.SafetyDailyState(
        user_id=user.id,
        safety_date=safety_date,
        status="pending",
        deadline_utc=local_deadline_utc(user, safety_date),
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        return (
            db.query(models.SafetyDailyState)
            .filter(
                models.SafetyDailyState.user_id == user.id,
                models.SafetyDailyState.safety_date == safety_date,
            )
            .one()
        )
    return row


def _find_qualifying_checkin(
    db: Session, user: "models.SafetyUser", safety_date: date, deadline_utc: datetime
) -> "models.SafetyCheckIn | None":
    """The earliest SafetyCheckIn for (user, safety_date) strictly before its deadline.

    "Qualifying" = its local safety day matches safety_date AND
    checked_in_at is strictly before that day's deadline — a check-in at or
    after the deadline is late and does not qualify (S5 leaves it to the
    evaluator to resolve to MISSED; late-check-in resolution belongs to S7).
    """
    deadline_utc = _as_aware_utc(deadline_utc)
    candidates = (
        db.query(models.SafetyCheckIn)
        .filter(
            models.SafetyCheckIn.user_id == user.id,
            models.SafetyCheckIn.checked_in_at < deadline_utc,
            models.SafetyCheckIn.checked_in_at >= deadline_utc - _QUALIFYING_CHECKIN_LOOKBACK,
        )
        .order_by(models.SafetyCheckIn.checked_in_at.asc())
        .all()
    )
    for checkin in candidates:
        if local_safety_date(user, checkin.checked_in_at) == safety_date:
            return checkin
    return None


def resolve_checkin(
    db: Session, user: "models.SafetyUser", checkin: "models.SafetyCheckIn"
) -> "models.SafetyDailyState":
    """Resolve a successful check-in's local safety day, per S5 state rules.

    - PENDING + checkin before that day's deadline -> SAFE.
    - MISSED is terminal in S5: never rewritten back to SAFE here, even if
      this check-in's own timestamp happens to be before the deadline (a
      day only reaches MISSED after its deadline has passed, so any
      check-in observed afterward is late by definition).
    - Already SAFE: no-op (idempotent).
    - A late check-in for a still-PENDING day changes nothing here; it is
      left for evaluate_user_deadline to resolve against the deadline.

    The PENDING -> SAFE transition is a conditional UPDATE ... WHERE
    status = 'pending', the same DB-authoritative pattern used by the
    evaluator: the in-memory `row` fetched above can go stale if another
    transaction (e.g. the evaluator) transitions it to MISSED in between,
    and an ordinary attribute-mutate-then-flush would blindly overwrite
    that with SAFE. The conditional UPDATE makes the transition a no-op
    when the row is no longer PENDING, and the row is always re-read
    afterward so the return value reflects whichever transaction actually
    won, never a stale in-memory guess.

    Only flushes, never commits — the caller (submit_check_in) commits the
    SafetyCheckIn insert and this state transition together, atomically.
    """
    safety_date = local_safety_date(user, checkin.checked_in_at)
    row = get_or_create_daily_state(db, user, safety_date)

    if row.status != "pending":
        return row

    deadline = _as_aware_utc(row.deadline_utc)
    checked_in_at = _as_aware_utc(checkin.checked_in_at)
    if checked_in_at < deadline:
        db.query(models.SafetyDailyState).filter(
            models.SafetyDailyState.id == row.id,
            models.SafetyDailyState.status == "pending",
        ).update(
            {
                "status": "safe",
                "checkin_id": checkin.id,
                "evaluated_at": datetime.now(timezone.utc),
            },
            synchronize_session=False,
        )
        db.flush()
        db.refresh(row)

    return row


def _resolve_pending_day_locked(
    db: Session, user: "models.SafetyUser", row: "models.SafetyDailyState", now: datetime
) -> None:
    """If `row` is PENDING and past its deadline, resolve it to SAFE or MISSED.

    Looks for an already-persisted qualifying check-in first — this is what
    makes a racing/recovering evaluator resolve to SAFE instead of MISSED
    when a valid on-time check-in already exists but was not yet reflected
    on the row (e.g. multi-day backfill catching up on a day that already
    had a legitimate check-in). The UPDATE is scoped to `status = 'pending'`
    so a concurrent transition (from another process, or from a racing
    check-in's own resolve_checkin) is a safe no-op here.
    """
    deadline = _as_aware_utc(row.deadline_utc)
    if row.status != "pending" or now < deadline:
        return

    qualifying = _find_qualifying_checkin(db, user, row.safety_date, deadline)
    new_status = "safe" if qualifying is not None else "missed"
    db.query(models.SafetyDailyState).filter(
        models.SafetyDailyState.id == row.id,
        models.SafetyDailyState.status == "pending",
    ).update(
        {
            "status": new_status,
            "checkin_id": qualifying.id if qualifying is not None else None,
            "evaluated_at": now,
        },
        synchronize_session=False,
    )
    db.flush()


def _first_eligible_safety_date(user: "models.SafetyUser") -> date:
    """The earliest local safety day this user is eligible for monitoring.

    SafetyUser.created_at is the persisted lifecycle fact marking when this
    user became eligible. If they were created strictly before that local
    day's own deadline, that day itself is eligible; if they were created
    at or after that deadline (it has already passed), monitoring starts
    the next local day instead -- otherwise a user could be backfilled a
    fake historical MISSED day for a deadline that occurred before they
    existed.
    """
    created_at = _as_aware_utc(user.created_at)
    created_local_date = local_safety_date(user, created_at)
    deadline_that_day = local_deadline_utc(user, created_local_date)
    if created_at < deadline_that_day:
        return created_local_date
    return created_local_date + timedelta(days=1)


def evaluate_user_deadline(
    db: Session, user: "models.SafetyUser", now_utc: datetime | None = None
) -> "models.SafetyDailyState | None":
    """Evaluate a user's safety days from their first eligible day through today.

    Recovery anchor: _first_eligible_safety_date(user) — no safety day
    before it is ever created. Every day in [anchor, today] is checked
    against a single up-front query of this user's existing rows in that
    range, so a legitimate gap (a day with no row, sitting between two days
    that do have rows) is detected and filled — not just the latest known
    day — while still costing one query plus a cheap in-memory lookup per
    call rather than a per-day round trip; a day with an existing row that
    is not "pending" is left untouched.
    """
    now = now_utc if now_utc is not None else datetime.now(timezone.utc)
    today = local_safety_date(user, now)
    anchor = _first_eligible_safety_date(user)

    if today < anchor:
        return None

    existing_by_date = {
        row.safety_date: row
        for row in (
            db.query(models.SafetyDailyState)
            .filter(
                models.SafetyDailyState.user_id == user.id,
                models.SafetyDailyState.safety_date >= anchor,
                models.SafetyDailyState.safety_date <= today,
            )
            .all()
        )
    }

    d = anchor
    while d <= today:
        row = existing_by_date.get(d)
        if row is None:
            row = get_or_create_daily_state(db, user, d)
        if row.status == "pending":
            _resolve_pending_day_locked(db, user, row, now)
        d += timedelta(days=1)

    db.commit()

    return (
        db.query(models.SafetyDailyState)
        .filter(
            models.SafetyDailyState.user_id == user.id,
            models.SafetyDailyState.safety_date == today,
        )
        .first()
    )


def evaluate_all_active_users(db: Session, now_utc: datetime | None = None) -> None:
    """Evaluate every active SafetyUser's safety days.

    Used by the periodic background trigger (see main.py). Each user is
    evaluated (and committed) independently, so a failure for one user
    (e.g. a corrupt/unknown timezone value) is logged and skipped rather
    than raised, and can never block evaluation of other users or crash the
    loop — it also never marks that user "safe", so the failure is visible
    (an indefinitely "pending"/stale row) rather than silently fabricating a
    safe outcome.
    """
    now = now_utc if now_utc is not None else datetime.now(timezone.utc)
    users = db.query(models.SafetyUser).filter(models.SafetyUser.is_active.is_(True)).all()
    for user in users:
        try:
            evaluate_user_deadline(db, user, now_utc=now)
        except Exception:
            db.rollback()
            logger.exception("safety deadline evaluation failed for user_id=%s", user.id)
