"""Telegram Bot Runtime — Phase T1B.

Webhook-based customer self-service chat flow. Customers authenticate with the
plain-text access_code issued via the admin Bot Engine (bot_admin.py), then
self-serve destination_url updates for their assigned 'url' slugs.

Scope (T1B):
  - url slugs: full self-service (view current destination, submit new one,
    confirm, update destination_url only).
  - media slugs: menu/state only. No file is ever received or uploaded from
    Telegram — the existing R2 upload flow (media_admin.py) is a browser-side
    presigned-PUT flow with no server-side "accept raw bytes" path, so a safe
    Telegram upload path does not yet exist. Replacement is reported to the
    customer as deferred.

Conversation state is held in an in-memory dict, acceptable for a single
uvicorn process (no --workers flag in this deployment) and acceptable to lose
on service restart (owner-approved for T1B).

No admin functionality is reachable through this module. No webhook is
auto-registered with Telegram — that remains a manual, explicitly-approved
step (setWebhook call) after deploy.
"""
import logging
import os
from collections import deque

import httpx
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

import models
from database import get_db

logger = logging.getLogger("bot_runtime")

_TELEGRAM_API_BASE = "https://api.telegram.org/bot{token}"

# ---------------------------------------------------------------------------
# In-memory conversation state — {chat_id: {...}}
# ---------------------------------------------------------------------------

_SESSIONS: dict[int, dict] = {}

# ---------------------------------------------------------------------------
# In-memory update_id dedup — bounded, no DB table (Telegram may redeliver an
# update if our response is slow or lost; skip reprocessing duplicates).
# ---------------------------------------------------------------------------

_SEEN_UPDATE_IDS: deque = deque(maxlen=500)


def _reset_to_slug_menu(session: dict) -> dict:
    return {
        "state": "awaiting_slug_selection",
        "bot_client_id": session["bot_client_id"],
        "slugs": session["slugs"],
    }


# ---------------------------------------------------------------------------
# Telegram send helper — fails safe if TELEGRAM_BOT_TOKEN is not configured
# ---------------------------------------------------------------------------

async def _send_message(chat_id: int, text: str) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        logger.error(
            "TELEGRAM_BOT_TOKEN is not configured — cannot send message to chat_id=%s",
            chat_id,
        )
        return
    url = _TELEGRAM_API_BASE.format(token=token) + "/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json={"chat_id": chat_id, "text": text})
            response.raise_for_status()
    except httpx.HTTPError as exc:
        logger.error("Failed to send Telegram message to chat_id=%s: %s", chat_id, exc)


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _get_active_assigned_slugs(bot_client_id: int, db: Session) -> list[dict]:
    """Active (non-archived), assigned slugs for a bot client, oldest-first."""
    rows = (
        db.query(models.BotClientSlug, models.RedirectLink)
        .join(models.RedirectLink, models.BotClientSlug.slug == models.RedirectLink.slug)
        .filter(models.BotClientSlug.bot_client_id == bot_client_id)
        .order_by(models.BotClientSlug.created_at.asc())
        .all()
    )
    return [
        {"slug": link.slug, "content_type": link.content_type, "notes": link.notes}
        for _, link in rows
        if link.is_archived is not True
    ]


def _format_slug_menu(slugs: list[dict]) -> str:
    lines = ["Your assigned slugs:"]
    for i, item in enumerate(slugs, start=1):
        label = item["notes"] or item["slug"]
        kind = "media slug" if item["content_type"] == "media" else "url slug"
        lines.append(f"{i}. ({label}) — {kind}")
    lines.append("\nReply with a number to select.")
    return "\n".join(lines)


def _parse_index(text: str, count: int) -> int | None:
    text = text.strip()
    if not text.isdigit():
        return None
    n = int(text)
    if n < 1 or n > count:
        return None
    return n - 1


def _current_media_status_text(slug: str, db: Session) -> str:
    sm = (
        db.query(models.SlugMedia)
        .filter(models.SlugMedia.slug == slug, models.SlugMedia.is_active == True)
        .first()
    )
    if not sm:
        return "no active media attached"
    asset = db.query(models.MediaAsset).filter(models.MediaAsset.id == sm.media_asset_id).first()
    if not asset:
        return "no active media attached"
    return asset.display_name or asset.original_filename


# ---------------------------------------------------------------------------
# Conversation state machine
# ---------------------------------------------------------------------------

async def _handle_message(chat_id: int, text: str, from_user: dict, db: Session) -> None:
    text = (text or "").strip()

    if text.lower() in ("/start", "start"):
        _SESSIONS[chat_id] = {"state": "awaiting_code"}
        await _send_message(chat_id, "Welcome to SHADZ. Please enter your access code.")
        return

    session = _SESSIONS.get(chat_id) or {"state": "awaiting_code"}
    state = session.get("state")

    if state == "awaiting_code":
        code = text.strip()
        client = (
            db.query(models.BotClient)
            .filter(models.BotClient.access_code == code, models.BotClient.is_active == True)
            .first()
        )
        if not client:
            await _send_message(chat_id, "Invalid or inactive access code. Please try again.")
            return

        telegram_user_id = from_user.get("id")
        if telegram_user_id is not None:
            client.telegram_user_id = str(telegram_user_id)
        client.telegram_username = from_user.get("username")
        db.commit()

        slugs = _get_active_assigned_slugs(client.id, db)
        if not slugs:
            _SESSIONS[chat_id] = {"state": "awaiting_code"}
            await _send_message(chat_id, "You're authenticated, but no active slugs are assigned to your account yet.")
            return

        _SESSIONS[chat_id] = {
            "state": "awaiting_slug_selection",
            "bot_client_id": client.id,
            "slugs": slugs,
        }
        await _send_message(chat_id, _format_slug_menu(slugs))
        return

    if state == "awaiting_slug_selection":
        slugs = session.get("slugs", [])
        idx = _parse_index(text, len(slugs))
        if idx is None:
            await _send_message(chat_id, f"Please reply with a number between 1 and {len(slugs)}.")
            return

        chosen = slugs[idx]
        link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == chosen["slug"]).first()
        if not link or link.is_archived is True:
            await _send_message(chat_id, "That slug is no longer available.")
            _SESSIONS[chat_id] = _reset_to_slug_menu(session)
            return

        if chosen["content_type"] == "media":
            status = _current_media_status_text(chosen["slug"], db)
            await _send_message(
                chat_id,
                f"Current media: {status}\n\n"
                "Media replacement via Telegram isn't available yet — please contact "
                "SHADZ support to update this slug's media. Reply with another number to "
                "select a different slug.",
            )
            _SESSIONS[chat_id] = session  # stay on the slug menu state
            return

        session["state"] = "awaiting_new_url"
        session["selected_slug"] = chosen["slug"]
        _SESSIONS[chat_id] = session
        await _send_message(
            chat_id,
            f"Current destination for '{chosen['slug']}':\n{link.destination_url}\n\n"
            "Reply with the new destination URL (must start with http:// or https://), "
            "or /cancel.",
        )
        return

    if state == "awaiting_new_url":
        if text.lower() == "/cancel":
            _SESSIONS[chat_id] = _reset_to_slug_menu(session)
            await _send_message(chat_id, "Cancelled.")
            return
        if not (text.startswith("http://") or text.startswith("https://")):
            await _send_message(chat_id, "That doesn't look like a valid URL — it must start with http:// or https://. Try again, or /cancel.")
            return

        session["pending_value"] = text
        session["state"] = "awaiting_confirmation"
        _SESSIONS[chat_id] = session
        await _send_message(
            chat_id,
            f"Update '{session['selected_slug']}' destination to:\n{text}\n\n"
            "Reply YES to confirm or NO to cancel.",
        )
        return

    if state == "awaiting_confirmation":
        answer = text.lower()
        if answer in ("yes", "y", "confirm"):
            link = (
                db.query(models.RedirectLink)
                .filter(models.RedirectLink.slug == session["selected_slug"])
                .first()
            )
            if not link or link.is_archived is True:
                await _send_message(chat_id, "That slug is no longer available.")
            else:
                link.destination_url = session["pending_value"]
                db.commit()
                await _send_message(chat_id, f"Done. '{session['selected_slug']}' now points to {session['pending_value']}.")
            _SESSIONS[chat_id] = _reset_to_slug_menu(session)
            return
        if answer in ("no", "n", "cancel"):
            _SESSIONS[chat_id] = _reset_to_slug_menu(session)
            await _send_message(chat_id, "Cancelled.")
            return
        await _send_message(chat_id, "Please reply YES to confirm or NO to cancel.")
        return

    # Unknown/expired state — restart cleanly.
    _SESSIONS[chat_id] = {"state": "awaiting_code"}
    await _send_message(chat_id, "Session expired. Please enter your access code.")


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def register_bot_webhook_routes(app) -> None:
    """Register the Telegram webhook route on the FastAPI app.

    Public route — no Basic Auth (Telegram cannot supply it). Protected
    instead by a mandatory shared-secret header check — TELEGRAM_WEBHOOK_SECRET
    must be configured or the route fails closed. No admin functionality is
    reachable through this route.
    """

    @app.post("/bot/telegram/webhook", include_in_schema=False)
    async def telegram_webhook(request: Request, db: Session = Depends(get_db)):
        secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET", "")
        if not secret:
            raise HTTPException(
                status_code=503,
                detail="Telegram webhook secret not configured",
            )
        header = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if header != secret:
            raise HTTPException(status_code=401, detail="Invalid webhook secret")

        body = await request.json()
        message = body.get("message") or body.get("edited_message")
        if not message:
            return {"ok": True}

        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            return {"ok": True}

        update_id = body.get("update_id")
        if update_id is not None:
            if update_id in _SEEN_UPDATE_IDS:
                return {"ok": True}
            _SEEN_UPDATE_IDS.append(update_id)

        text = message.get("text") or ""
        from_user = message.get("from") or {}

        try:
            await _handle_message(chat_id, text, from_user, db)
        except Exception:
            logger.exception("Unhandled error processing update_id=%s chat_id=%s", update_id, chat_id)

        return {"ok": True}
