"""Safety Engine v1 Phase S6.1 — minimal SafetyUser admin configuration.

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
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from database import get_db
from safety_notify import acknowledge_sos, resolve_sos


class SafetyUserOut(BaseModel):
    """Deliberately minimal -- nfc_token (the physical-token lookup key,
    see models.SafetyUser) is never exposed by this admin endpoint."""
    id:                int
    display_name:      str
    is_active:         bool
    telegram_chat_id:  int | None

    model_config = {"from_attributes": True}


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


def register_safety_admin_routes(admin_router) -> None:
    """Register the Safety Engine admin routes onto admin_router."""

    @admin_router.get("/safety/users", response_model=list[SafetyUserOut])
    def list_safety_users(db: Session = Depends(get_db)):
        """List every SafetyUser, for looking up the id to configure."""
        return db.query(models.SafetyUser).order_by(models.SafetyUser.id).all()

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
        return user

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
