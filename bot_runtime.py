"""Telegram Bot Runtime — Phase T1B + T1C.

Webhook-based customer self-service chat flow. Customers authenticate with the
plain-text access_code issued via the admin Bot Engine (bot_admin.py), then
self-serve their assigned 'url' and 'media' slugs.

Scope:
  - url slugs (T1B): full self-service (view current destination, submit new
    one, confirm, update destination_url only).
  - media slugs (T1C): customer sends a replacement file (photo/document/
    video/GIF); it's downloaded from Telegram via getFile, validated against
    the same ALLOWED_MEDIA_TYPES mime allowlist used by the browser upload
    flow, uploaded to R2, and swapped in as the new active SlugMedia record.

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
from urllib.parse import urlparse

import httpx
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

import models
from database import get_db
# T1C intentionally reuses these existing media_admin storage helpers instead
# of extracting a shared module — avoids a broad refactor for a single
# consumer. Future cleanup: move into a shared media storage module if a
# third caller needs them.
from media_admin import (
    ALLOWED_MEDIA_TYPES,
    _get_r2_client,
    _make_public_url,
    _make_storage_key,
)

logger = logging.getLogger("bot_runtime")

_TELEGRAM_API_BASE = "https://api.telegram.org/bot{token}"

# Telegram's standard (non-local) Bot API enforces a hard 20 MB cap on file
# downloads via getFile — matching it here means we reject early instead of
# attempting a download that Telegram itself would already refuse.
_MAX_TELEGRAM_MEDIA_BYTES = 20 * 1024 * 1024

_EXT_BY_MIME = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "video/mp4": "mp4",
    "video/quicktime": "mov",
    "video/webm": "webm",
    "image/gif": "gif",
}

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


# ---------------------------------------------------------------------------
# Link Safety Guard (Phase T1F) — blocks customers from pointing a bot-managed
# url slug back at SHADZ itself or an internal/local address, which would
# otherwise allow slug chaining or route confusion.
# ---------------------------------------------------------------------------

_BLOCKED_HOSTS = {"shadz.io", "www.shadz.io", "localhost", "127.0.0.1", "0.0.0.0"}


def _is_blocked_destination_url(url: str) -> bool:
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return True
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return True
    return hostname in _BLOCKED_HOSTS


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
# Media replacement helpers (Phase T1C)
# ---------------------------------------------------------------------------

def _extract_media_candidate(message: dict) -> tuple[str, str, int | None, str | None] | None:
    """Pull (file_id, mime_type, file_size, file_name) out of a Telegram message.

    Only document / video / animation / photo are considered. Returns None if
    the message carries no supported media field (e.g. plain text, voice,
    sticker, contact, location).
    """
    document = message.get("document")
    if document:
        return (
            document.get("file_id"),
            document.get("mime_type") or "",
            document.get("file_size"),
            document.get("file_name"),
        )

    video = message.get("video")
    if video:
        return (
            video.get("file_id"),
            video.get("mime_type") or "video/mp4",
            video.get("file_size"),
            video.get("file_name"),
        )

    animation = message.get("animation")
    if animation:
        return (
            animation.get("file_id"),
            animation.get("mime_type") or "video/mp4",
            animation.get("file_size"),
            animation.get("file_name"),
        )

    photos = message.get("photo")
    if photos:
        largest = photos[-1]
        return (largest.get("file_id"), "image/jpeg", largest.get("file_size"), None)

    return None


def _media_type_for_mime(mime_type: str) -> str | None:
    """Reverse-lookup against media_admin.ALLOWED_MEDIA_TYPES."""
    for media_type, mimes in ALLOWED_MEDIA_TYPES.items():
        if mime_type in mimes:
            return media_type
    return None


def _default_filename(media_type: str, mime_type: str) -> str:
    ext = _EXT_BY_MIME.get(mime_type, media_type)
    return f"telegram_{media_type}.{ext}"


async def _download_telegram_file(file_id: str) -> bytes:
    """Fetch raw bytes for a Telegram file_id via getFile + the file download URL."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not configured")
    async with httpx.AsyncClient(timeout=30) as client:
        get_file_resp = await client.get(
            _TELEGRAM_API_BASE.format(token=token) + "/getFile",
            params={"file_id": file_id},
        )
        get_file_resp.raise_for_status()
        try:
            payload = get_file_resp.json()
        except ValueError as exc:
            raise RuntimeError("getFile response was not valid JSON") from exc

        if payload.get("ok") is not True:
            raise RuntimeError("getFile response was not ok")

        file_path = (payload.get("result") or {}).get("file_path")
        if not file_path:
            raise RuntimeError("getFile response missing file_path")

        download_url = f"https://api.telegram.org/file/bot{token}/{file_path}"
        file_resp = await client.get(download_url)
        file_resp.raise_for_status()
        return file_resp.content


def _upload_bytes_to_r2(storage_key: str, data: bytes, mime_type: str) -> None:
    """Server-side R2 upload for bot-sourced bytes (distinct from the browser
    presigned-PUT flow in media_admin.py, which never routes bytes through
    the VPS)."""
    client = _get_r2_client()
    bucket = os.environ.get("R2_BUCKET_NAME", "shadz-media")
    client.put_object(Bucket=bucket, Key=storage_key, Body=data, ContentType=mime_type)


# ---------------------------------------------------------------------------
# Conversation state machine
# ---------------------------------------------------------------------------

async def _handle_message(chat_id: int, text: str, from_user: dict, db: Session, message: dict) -> None:
    text = (text or "").strip()

    if text.lower() in ("/start", "start"):
        _SESSIONS[chat_id] = {"state": "awaiting_code"}
        await _send_message(chat_id, "Welcome to SHADZ. Please enter your access code.")
        return

    session = _SESSIONS.get(chat_id) or {"state": "awaiting_code"}
    state = session.get("state")

    # Phase T1G: a client authenticated earlier in this session may have been
    # deactivated since — re-check on every authenticated action, not just at
    # login, so deactivation takes effect immediately instead of at next login.
    if state != "awaiting_code":
        bot_client_id = session.get("bot_client_id")
        if bot_client_id is not None:
            active_client = (
                db.query(models.BotClient)
                .filter(models.BotClient.id == bot_client_id, models.BotClient.is_active.is_(True))
                .first()
            )
            if not active_client:
                _SESSIONS[chat_id] = {"state": "awaiting_code"}
                await _send_message(
                    chat_id,
                    "Your access has been deactivated. Please contact the admin, "
                    "or enter a new access code if you have one.",
                )
                return

    if state == "awaiting_code":
        code = text.strip()
        client = (
            db.query(models.BotClient)
            .filter(models.BotClient.access_code == code, models.BotClient.is_active.is_(True))
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
            session["state"] = "awaiting_media_upload"
            session["selected_slug"] = chosen["slug"]
            _SESSIONS[chat_id] = session
            await _send_message(
                chat_id,
                f"Current media: {status}\n\n"
                "Send a replacement file (photo, document, video, or GIF) to update "
                "this slug's media, or /cancel.",
            )
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
        if _is_blocked_destination_url(text):
            await _send_message(
                chat_id,
                "This link cannot be used because it points back to SHADZ or an internal address. "
                "Please send an external public link instead.",
            )
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

    if state == "awaiting_media_upload":
        if text.lower() == "/cancel":
            _SESSIONS[chat_id] = _reset_to_slug_menu(session)
            await _send_message(chat_id, "Cancelled.")
            return

        candidate = _extract_media_candidate(message)
        if candidate is None:
            await _send_message(
                chat_id,
                "Please send a photo, document, video, or GIF to replace the media — "
                "plain text isn't accepted. Or reply /cancel.",
            )
            return

        file_id, mime_type, reported_size, file_name = candidate

        if not file_id:
            await _send_message(
                chat_id,
                "That file isn't supported. Please send a photo, document, video, or GIF, "
                "or reply /cancel.",
            )
            return

        media_type = _media_type_for_mime(mime_type)
        if media_type is None:
            await _send_message(
                chat_id,
                f"That file type ({mime_type or 'unknown'}) isn't supported. "
                "Supported: JPEG/PNG/WEBP images, MP4/QuickTime/WEBM video, GIF.",
            )
            return

        if reported_size is not None and reported_size > _MAX_TELEGRAM_MEDIA_BYTES:
            await _send_message(
                chat_id,
                f"That file is too large ({reported_size // (1024 * 1024)} MB). "
                f"Max supported size is {_MAX_TELEGRAM_MEDIA_BYTES // (1024 * 1024)} MB.",
            )
            return

        slug = session["selected_slug"]
        link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
        if not link or link.is_archived is True or link.content_type != "media":
            await _send_message(chat_id, "That slug is no longer available.")
            _SESSIONS[chat_id] = _reset_to_slug_menu(session)
            return

        await _send_message(chat_id, "Uploading...")

        try:
            data = await _download_telegram_file(file_id)
        except Exception:
            logger.exception(
                "Telegram file download failed for chat_id=%s file_id=%s", chat_id, file_id
            )
            await _send_message(chat_id, "Couldn't download that file from Telegram. Please try again.")
            return

        if len(data) > _MAX_TELEGRAM_MEDIA_BYTES:
            await _send_message(chat_id, "That file is too large. Please send a smaller file.")
            return

        safe_name = file_name or _default_filename(media_type, mime_type)
        storage_key = _make_storage_key(media_type, safe_name)
        public_url = _make_public_url(storage_key)

        try:
            _upload_bytes_to_r2(storage_key, data, mime_type)
        except Exception:
            logger.exception("R2 upload failed for chat_id=%s slug=%s", chat_id, slug)
            await _send_message(chat_id, "Upload failed. Please try again in a moment.")
            return

        try:
            asset = models.MediaAsset(
                media_type=media_type,
                storage_provider="r2",
                storage_key=storage_key,
                public_url=public_url,
                original_filename=safe_name,
                mime_type=mime_type,
                file_size=len(data),
            )
            db.add(asset)
            db.flush()

            (db.query(models.SlugMedia)
               .filter(models.SlugMedia.slug == slug, models.SlugMedia.is_active == True)
               .update({"is_active": False}))

            sm = models.SlugMedia(slug=slug, media_asset_id=asset.id, is_active=True)
            db.add(sm)
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("DB commit failed for chat_id=%s slug=%s", chat_id, slug)
            await _send_message(chat_id, "Something went wrong saving the new media. Please try again.")
            return

        await _send_message(chat_id, f"Done. Media for '{slug}' has been replaced.")
        _SESSIONS[chat_id] = _reset_to_slug_menu(session)
        return

    if state == "awaiting_confirmation":
        answer = text.lower()
        if answer in ("yes", "y", "confirm"):
            link = (
                db.query(models.RedirectLink)
                .filter(models.RedirectLink.slug == session["selected_slug"])
                .first()
            )
            if not link or link.is_archived is True or link.content_type != "url":
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
            await _handle_message(chat_id, text, from_user, db, message)
        except Exception:
            logger.exception("Unhandled error processing update_id=%s chat_id=%s", update_id, chat_id)

        return {"ok": True}
