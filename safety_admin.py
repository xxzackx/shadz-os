"""Safety Engine v1 Phase S6.1 / S7 / S8 — Admin Safety module.

Phase S8 (SHADZ Admin Safety Module + Hardening) adds the missing read/audit
and configuration surface the Admin Panel needs so that "immediate incident
response" (Admin Telegram) and "management / visibility / configuration /
audit / history" (Admin Panel) are properly split:
  - GET   /admin/safety/overview                       counts for the Admin
                                                          Panel home screen
  - PATCH /admin/safety/users/{id}                      activate/deactivate,
                                                          daily deadline,
                                                          early reminder
                                                          minutes (timezone
                                                          stays read-only,
                                                          see below)
  - GET   /admin/safety/checkins                        raw check-in history
                                                          (GPS included)
  - GET   /admin/safety/daily-states                    per-day
                                                          pending/safe/missed
                                                          history
  - GET   /admin/safety/alerts                          early-reminder /
                                                          missed-checkin
                                                          SafetyAlert history
  - GET   /admin/safety/late-checkin-alerts              late-checkin notice
                                                          history
None of these introduce a new state machine or duplicate an existing
transition -- they are all read-only projections of existing tables (see
models.py: SafetyCheckIn, SafetyDailyState, SafetyAlert,
SafetyLateCheckinAlert), except the new SafetyUser PATCH, which only ever
assigns plain attributes read fresh by safety_deadline.py/safety_notify.py on
their next evaluation -- it never writes SafetyDailyState/SafetyAlert/
SafetyEmergency itself. SafetyUser creation/deletion remains out of scope
(unchanged from S6.1) -- provisioning is still done only outside the Admin
Panel (e.g. script/DB insert).

Before S6.1 there was no admin path of any kind for SafetyUser: no create,
list, or update route existed anywhere in the app (SafetyUser rows are
otherwise only ever created directly, e.g. via a script or DB insert). S6.1
introduces models.SafetyUser.telegram_chat_id (each SafetyUser's own early-
reminder Telegram recipient, see safety_telegram._user_chat_id) which is
useless in production unless Admin actually has a way to set it, so this
module adds exactly the two smallest routes needed for that:
  - GET  /admin/safety/users                       list, for lookup by id
  - PATCH /admin/safety/users/{id}/telegram-chat-id  the one writable field

No create/delete route and no other field is made writable here -- SafetyUser
provisioning (display_name, timezone, deadline, nfc_token, etc.) stays out of
scope for this phase. This is deliberately a standalone Safety Engine admin
surface -- it never touches BotClient or bot_admin.py.

Call register_safety_admin_routes(admin_router) in main.py to wire these onto
the existing admin_router. Routes inherit the router's /admin prefix and
verify_admin dependency unchanged.

Phase S7 adds the SOS acknowledge/resolve lifecycle to this same module:
  - GET   /admin/safety/emergencies                  list, for lookup by id
  - POST  /admin/safety/emergencies/{id}/acknowledge  open -> acknowledged
  - POST  /admin/safety/emergencies/{id}/resolve      acknowledged -> resolved (strict)
The actual state-transition logic (idempotent conditional UPDATEs) lives in
safety_notify.acknowledge_sos / resolve_sos, reused here rather than
duplicated, exactly like every other Safety Engine write path in this
codebase. These routes inherit admin_router's Basic Auth the same way as the
telegram-chat-id route above -- no public/unauthenticated SOS-management
endpoint is introduced.
"""
import os
from datetime import date, datetime, time, timezone

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import models
from database import get_db
from safety_deadline import local_safety_date
from safety_notify import acknowledge_sos, resolve_sos


def _safety_checkin_url(user: "models.SafetyUser") -> str:
    """The full canonical public Safety Check-in entry URL for a
    SafetyUser, for Admin to copy into the normal Redirect Engine's
    destination_url -- preserves the locked S2 architecture unchanged
    (permanent SHADZ redirect slug -> GET /safety/c/{secure_token}) rather
    than introducing any parallel routing.

    Base URL follows the same env-var-with-default pattern as
    media_admin._make_public_url's R2_PUBLIC_BASE_URL -- overridable via
    SHADZ_PUBLIC_BASE_URL, defaulting to the documented production domain
    (see CLAUDE.md) so this never needs a literal hostname hard-coded into
    request-handling logic.

    Only ever called with user.secure_token (the existing S2 public-entry
    key) -- never nfc_token -- and the token value itself is not exposed by
    any Safety admin schema; only this fully-assembled URL is.
    """
    base = os.environ.get("SHADZ_PUBLIC_BASE_URL", "https://shadz.io").rstrip("/")
    return f"{base}/safety/c/{user.secure_token}"


class SafetyUserOut(BaseModel):
    """S8 extends this with the rest of a SafetyUser's own visible
    configuration (timezone, daily_deadline, early_reminder_minutes) so the
    Admin Panel can show it -- still deliberately excludes nfc_token
    (physical-token lookup key) and secure_token (public-entry key) in raw
    form, neither of which Admin ever needs to see or manage. checkin_url
    is the one derived, safe-to-share artifact of secure_token: the full
    browser entry URL, for pasting into a normal Redirect Engine
    destination_url -- read-only, no edit/regenerate action exists here.

    timezone here is visibility-only: it is not a field on
    SafetyUserConfigUpdateRequest below, so no PATCH can change it in S8 v1
    (see that class's docstring for why)."""
    id:                      int
    display_name:            str
    is_active:               bool
    timezone:                str
    daily_deadline:          time
    early_reminder_minutes:  int
    telegram_chat_id:        int | None
    checkin_url:             str

    model_config = {"from_attributes": True}


class SafetyUserConfigUpdateRequest(BaseModel):
    """Body for PATCH /admin/safety/users/{id} (S8).

    Partial update: every field is optional and a field left out of the
    request body is left unchanged -- unlike the telegram-chat-id route
    below, there is no field here where "omitted" and "explicitly cleared"
    need to mean different things, so plain Optional-with-None-means-skip is
    the right (and simpler) contract, deliberately not merged into that
    route's stricter set/clear semantics.

    timezone is deliberately NOT a field here -- read-only in S8 v1. Unlike
    daily_deadline (whose effect is fully contained inside one already-
    persisted SafetyDailyState.deadline_utc, computed once at row-creation
    time and never revisited), timezone is read live and repeatedly
    throughout the engine -- safety_deadline.local_safety_date() calls
    ZoneInfo(user.timezone) on every check-in, every evaluator tick, and
    every S8 overview computation to decide *which* safety_date a UTC
    instant belongs to. Changing it would immediately change which
    safety_date new activity resolves against, while every already-created
    SafetyDailyState row keeps its old safety_date/deadline_utc computed
    under the old timezone -- there is no safe "applies only to future rows"
    story for timezone the way there is for daily_deadline, so admin
    editing of it is out of scope for S8 v1. It remains visible in
    SafetyUserOut for visibility purposes only.

    IMPORTANT -- effective-date semantics for daily_deadline: it is a plain
    SafetyUser attribute. Changing it here takes effect only for
    SafetyDailyState rows created *after* this PATCH (safety_deadline.py
    reads the user's current daily_deadline each time it creates a new
    day's row and bakes the result into that row's own deadline_utc). Any
    SafetyDailyState row that already exists -- including its deadline_utc,
    status, and any SafetyAlert/SafetyLateCheckinAlert tied to it -- is
    never rewritten by this route and is unaffected by this PATCH. There is
    no retroactive recompute and no new state transition here.

    early_reminder_minutes is bounded to a single calendar day
    (0-1440 minutes) -- no existing repo contract defines a stricter bound,
    and this is the natural domain limit for "minutes before a daily
    deadline".

    extra="forbid": a request body containing timezone (or any other
    unknown field) must fail closed with 422, not be silently ignored --
    a caller trying to set timezone should get a clear rejection, not a
    quiet no-op that could be mistaken for success.
    """
    model_config = {"extra": "forbid"}

    is_active:               bool | None = None
    daily_deadline:          time | None = None
    early_reminder_minutes:  int | None = Field(default=None, ge=0, le=1440)


class SafetyUserTelegramChatIdUpdateRequest(BaseModel):
    """Body for PATCH /admin/safety/users/{id}/telegram-chat-id.

    telegram_chat_id is required but nullable, not optional-with-a-default:
    {"telegram_chat_id": 123} sets it, {"telegram_chat_id": null} explicitly
    clears it (the user then gets no early reminders -- see
    safety_telegram._user_chat_id, which never falls back to Admin), and an
    empty body {} is rejected with 422 rather than silently defaulting to a
    clear -- a caller must always say which of the two they mean.
    """
    telegram_chat_id: int | None


class SafetyEmergencyOut(BaseModel):
    """Phase S7 -- admin-facing view of one SOS. Deliberately does not
    expose SafetyEmergency.notification_claimed_at (an internal delivery
    lease, not an operational/audit fact) or telegram_message_id."""
    id:                  int
    user_id:             int
    status:              str
    triggered_at:        datetime
    latitude:             float | None
    longitude:            float | None
    accuracy_m:           float | None
    acknowledged_at:      datetime | None
    resolved_at:          datetime | None
    last_notified_at:     datetime | None

    model_config = {"from_attributes": True}


class SafetyOverviewOut(BaseModel):
    """S8 -- Admin Panel home-screen counts. Computed on demand from the
    existing tables (no new persisted state); "today" is evaluated per user
    in that user's own local safety date, via safety_deadline.local_safety_date
    -- the same helper the deadline engine itself uses -- never the server's
    UTC date."""
    active_safety_users:          int
    today_pending:                int
    today_safe:                   int
    today_missed:                 int
    today_no_state_yet:           int
    open_missed_checkin_alerts:   int
    active_sos_incidents:         int


class SafetyCheckInOut(BaseModel):
    """S8 -- read-only check-in history, GPS included (see S4: mandatory
    for every public_web check-in)."""
    id:              int
    user_id:         int
    checked_in_at:   datetime
    latitude:        float | None
    longitude:       float | None
    accuracy_m:      float | None
    source:          str

    model_config = {"from_attributes": True}


class SafetyDailyStateOut(BaseModel):
    """S8 -- read-only per-user-per-day pending/safe/missed history (Phase
    S5's SafetyDailyState). Never mutated by this admin module -- the
    deadline engine (safety_deadline.py) remains the sole writer."""
    id:              int
    user_id:         int
    safety_date:     date
    status:          str
    checkin_id:      int | None
    evaluated_at:    datetime | None

    model_config = {"from_attributes": True}


class SafetyAlertOut(BaseModel):
    """S8 -- read-only early-reminder / missed-checkin alert history
    (Phase S6/S7's SafetyAlert). Deliberately excludes
    delivery_claimed_at (internal delivery lease) and telegram_message_id
    (internal delivery detail), matching SafetyEmergencyOut's precedent
    above."""
    id:                    int
    user_id:               int
    safety_date:           date
    alert_type:            str
    status:                str
    triggered_at:          datetime
    notified_at:           datetime | None
    resolved_at:           datetime | None
    resolved_checkin_id:   int | None

    model_config = {"from_attributes": True}


class SafetyLateCheckinAlertOut(BaseModel):
    """S8 -- read-only late-checkin notice history (Phase S6.1's
    SafetyLateCheckinAlert). No status/resolution field exists on this
    table -- a late check-in is a fact, not a state machine -- so this is
    a pure notification-history record. Excludes delivery_claimed_at for
    the same reason as SafetyAlertOut above."""
    id:              int
    user_id:         int
    safety_date:     date
    checkin_id:      int
    triggered_at:    datetime
    notified_at:     datetime | None

    model_config = {"from_attributes": True}


def _to_safety_user_out(user: "models.SafetyUser") -> SafetyUserOut:
    """Build the admin-facing SafetyUserOut for one SafetyUser, including
    the derived checkin_url -- SafetyUserOut.model_config's from_attributes
    alone can't populate checkin_url since it isn't a real SafetyUser
    column, so every route below constructs it through this one helper
    rather than returning the raw ORM row directly."""
    return SafetyUserOut(
        id=user.id,
        display_name=user.display_name,
        is_active=user.is_active,
        timezone=user.timezone,
        daily_deadline=user.daily_deadline,
        early_reminder_minutes=user.early_reminder_minutes,
        telegram_chat_id=user.telegram_chat_id,
        checkin_url=_safety_checkin_url(user),
    )


def register_safety_admin_routes(admin_router) -> None:
    """Register the Safety Engine admin routes onto admin_router."""

    @admin_router.get("/safety/users", response_model=list[SafetyUserOut])
    def list_safety_users(db: Session = Depends(get_db)):
        """List every SafetyUser, for looking up the id to configure."""
        users = db.query(models.SafetyUser).order_by(models.SafetyUser.id).all()
        return [_to_safety_user_out(u) for u in users]

    @admin_router.patch("/safety/users/{safety_user_id}", response_model=SafetyUserOut)
    def update_safety_user_config(
        safety_user_id: int,
        payload: SafetyUserConfigUpdateRequest,
        db: Session = Depends(get_db),
    ):
        """S8 -- admin-side activation/deactivation and reminder
        configuration (daily_deadline, early_reminder_minutes).
        Partial update: any field omitted from the request body is left
        unchanged. Deliberately separate from the telegram-chat-id route
        below -- that route's explicit set-vs-clear-vs-omit contract for a
        single nullable field is a different (and stricter) semantic than
        this route's plain "omitted = unchanged" partial update, so they are
        not merged.

        timezone is intentionally not writable here -- see
        SafetyUserConfigUpdateRequest's docstring for why (it is read live
        and repeatedly throughout the engine, unlike daily_deadline, so
        there is no safe "applies only to future rows" story for it in S8
        v1). It remains visible (read-only) via SafetyUserOut.

        Only ever assigns plain SafetyUser attributes -- this route never
        writes SafetyDailyState/SafetyAlert/SafetyEmergency/
        SafetyLateCheckinAlert itself and introduces no new state-machine
        transition. Does not create or delete SafetyUser rows --
        provisioning remains out of scope, unchanged from S6.1.

        Effective-date semantics (daily_deadline): this field is read fresh
        only at the moment safety_deadline.py creates a *new*
        SafetyDailyState row for a day that doesn't have one yet, and that
        row's own deadline_utc is computed and persisted once at creation
        time (see safety_deadline.get_or_create_daily_state /
        local_deadline_utc). So a change made here takes effect for
        SafetyDailyState rows created from this point on -- it is never
        applied retroactively: any day that already has a row keeps that
        row's deadline_utc, status, and any linked SafetyAlert/
        SafetyLateCheckinAlert exactly as they were, with no recompute.

        No-op guard: if the request body changes nothing (all fields
        omitted, or every provided value already matches the current row),
        this route makes no write at all -- updated_at is not bumped and no
        commit happens, so an empty/no-op PATCH can never look like a real
        configuration change in SafetyUser's own history.
        """
        user = db.query(models.SafetyUser).filter(models.SafetyUser.id == safety_user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"SafetyUser {safety_user_id} not found")

        changed = False

        if payload.daily_deadline is not None and payload.daily_deadline != user.daily_deadline:
            user.daily_deadline = payload.daily_deadline
            changed = True

        if (
            payload.early_reminder_minutes is not None
            and payload.early_reminder_minutes != user.early_reminder_minutes
        ):
            user.early_reminder_minutes = payload.early_reminder_minutes
            changed = True

        if payload.is_active is not None and payload.is_active != user.is_active:
            user.is_active = payload.is_active
            changed = True

        if changed:
            user.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(user)
        return _to_safety_user_out(user)

    @admin_router.patch("/safety/users/{safety_user_id}/telegram-chat-id", response_model=SafetyUserOut)
    def update_safety_user_telegram_chat_id(
        safety_user_id: int,
        payload: SafetyUserTelegramChatIdUpdateRequest,
        db: Session = Depends(get_db),
    ):
        """Set or clear a SafetyUser's own early-reminder Telegram chat id.

        Only telegram_chat_id is writable here -- every other SafetyUser
        field is untouched.
        """
        user = db.query(models.SafetyUser).filter(models.SafetyUser.id == safety_user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail=f"SafetyUser {safety_user_id} not found")

        user.telegram_chat_id = payload.telegram_chat_id
        db.commit()
        db.refresh(user)
        return _to_safety_user_out(user)

    @admin_router.get("/safety/emergencies", response_model=list[SafetyEmergencyOut])
    def list_safety_emergencies(db: Session = Depends(get_db)):
        """List every SOS (SafetyEmergency), most recent first -- for
        looking up the id to acknowledge/resolve. No filtering by status:
        historical (already-resolved) SOS rows remain visible here, so this
        doubles as the auditable SOS history required by Phase S7."""
        return (
            db.query(models.SafetyEmergency)
            .order_by(models.SafetyEmergency.triggered_at.desc())
            .all()
        )

    @admin_router.post(
        "/safety/emergencies/{emergency_id}/acknowledge", response_model=SafetyEmergencyOut
    )
    def acknowledge_safety_emergency(emergency_id: int, db: Session = Depends(get_db)):
        """Phase S7 -- SHADZ Admin acknowledges an open SOS. Idempotent: a
        repeat call, or a call on an already-resolved SOS, is a safe no-op
        that just returns the current (unchanged) state -- see
        safety_notify.acknowledge_sos. Does not stop SOS escalation; only
        resolve does."""
        emergency = acknowledge_sos(db, emergency_id, datetime.now(timezone.utc))
        if emergency is None:
            raise HTTPException(status_code=404, detail=f"SafetyEmergency {emergency_id} not found")
        return emergency

    @admin_router.post(
        "/safety/emergencies/{emergency_id}/resolve", response_model=SafetyEmergencyOut
    )
    def resolve_safety_emergency(emergency_id: int, db: Session = Depends(get_db)):
        """Phase S7 -- SHADZ Admin resolves an SOS. The locked lifecycle is
        strictly open -> acknowledged -> resolved, so a still-'open'
        emergency must be acknowledged first -- resolve_sos leaves an open
        row untouched, and this route rejects that case with 409 Conflict
        rather than silently no-opping or fabricating a resolution.
        Idempotent once resolved: a repeat call on an already-resolved
        emergency is a safe no-op that just returns the current (unchanged)
        state -- see safety_notify.resolve_sos. Stops SOS escalation -- see
        safety_notify._SOS_ESCALATION_STATUSES.

        Fail-closed against a TOCTOU race: resolve_sos only transitions a
        row it finds 'acknowledged' at the moment of its own UPDATE, then
        re-queries and returns whatever the row's status now is. If a
        concurrent request changed the row between this request's failed
        UPDATE and its re-query (e.g. this call saw 'open', updated zero
        rows, and a second request acknowledged it in between), the
        returned row would be 'acknowledged' -- correct, but NOT actually
        resolved by *this* call. Checking for anything other than
        'resolved' (rather than only checking for 'open') is what closes
        that gap: this call reports 409 unless the emergency is actually
        resolved by the time it returns, never a false 200."""
        emergency = resolve_sos(db, emergency_id, datetime.now(timezone.utc))
        if emergency is None:
            raise HTTPException(status_code=404, detail=f"SafetyEmergency {emergency_id} not found")
        if emergency.status != "resolved":
            raise HTTPException(
                status_code=409,
                detail="SOS must be acknowledged before it can be resolved",
            )
        return emergency

    @admin_router.get("/safety/overview", response_model=SafetyOverviewOut)
    def get_safety_overview(db: Session = Depends(get_db)):
        """S8 -- Admin Panel home-screen counts: active SafetyUsers, today's
        check-in status breakdown (per user's own local safety date, via
        safety_deadline.local_safety_date), open (unresolved) missed-checkin
        alerts, and active (open or acknowledged) SOS incidents. Purely a
        read-only aggregation of existing tables -- writes nothing."""
        now_utc = datetime.now(timezone.utc)
        active_users = (
            db.query(models.SafetyUser).filter(models.SafetyUser.is_active.is_(True)).all()
        )

        counts = {"pending": 0, "safe": 0, "missed": 0, "no_state_yet": 0}
        for user in active_users:
            today = local_safety_date(user, now_utc)
            state = (
                db.query(models.SafetyDailyState)
                .filter(
                    models.SafetyDailyState.user_id == user.id,
                    models.SafetyDailyState.safety_date == today,
                )
                .first()
            )
            counts["no_state_yet" if state is None else state.status] += 1

        open_missed_checkin_alerts = (
            db.query(models.SafetyAlert)
            .filter(
                models.SafetyAlert.alert_type == "missed_checkin",
                models.SafetyAlert.status == "open",
            )
            .count()
        )
        active_sos_incidents = (
            db.query(models.SafetyEmergency)
            .filter(models.SafetyEmergency.status.in_(["open", "acknowledged"]))
            .count()
        )

        return SafetyOverviewOut(
            active_safety_users=len(active_users),
            today_pending=counts["pending"],
            today_safe=counts["safe"],
            today_missed=counts["missed"],
            today_no_state_yet=counts["no_state_yet"],
            open_missed_checkin_alerts=open_missed_checkin_alerts,
            active_sos_incidents=active_sos_incidents,
        )

    @admin_router.get("/safety/checkins", response_model=list[SafetyCheckInOut])
    def list_safety_checkins(db: Session = Depends(get_db)):
        """S8 -- read-only check-in history (Daily Check-in History), most
        recent first, GPS included."""
        return (
            db.query(models.SafetyCheckIn)
            .order_by(models.SafetyCheckIn.checked_in_at.desc())
            .all()
        )

    @admin_router.get("/safety/daily-states", response_model=list[SafetyDailyStateOut])
    def list_safety_daily_states(db: Session = Depends(get_db)):
        """S8 -- read-only per-user-per-day pending/safe/missed history
        (Daily Check-in History), most recent day first. Never mutated
        here -- safety_deadline.py remains the sole writer of
        SafetyDailyState."""
        return (
            db.query(models.SafetyDailyState)
            .order_by(models.SafetyDailyState.safety_date.desc(), models.SafetyDailyState.id.desc())
            .all()
        )

    @admin_router.get("/safety/alerts", response_model=list[SafetyAlertOut])
    def list_safety_alerts(db: Session = Depends(get_db)):
        """S8 -- read-only Safety Alert History: every early-reminder and
        missed-checkin SafetyAlert, most recent first, open and resolved
        alike -- this is audit/history, not an action queue. Never mutated
        here -- safety_notify.py remains the sole writer of SafetyAlert."""
        return (
            db.query(models.SafetyAlert)
            .order_by(models.SafetyAlert.triggered_at.desc())
            .all()
        )

    @admin_router.get("/safety/late-checkin-alerts", response_model=list[SafetyLateCheckinAlertOut])
    def list_safety_late_checkin_alerts(db: Session = Depends(get_db)):
        """S8 -- read-only late-checkin notice history (Safety Alert
        History), most recent first. Never mutated here -- safety_notify.py
        remains the sole writer of SafetyLateCheckinAlert."""
        return (
            db.query(models.SafetyLateCheckinAlert)
            .order_by(models.SafetyLateCheckinAlert.triggered_at.desc())
            .all()
        )
