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
"""
from fastapi import Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from database import get_db


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
