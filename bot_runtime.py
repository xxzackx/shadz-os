"""Telegram Bot Runtime — Phase T1B + T1C + Activation Engine v1 Phase A2 + A3.

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
  - activation entry (Phase A2): builds the Telegram deep link used by the
    public slug resolver's Activation Gateway, and recognises the resulting
    /start payload to show the activation entry message.
  - activation client resolution (Phase A3): on the "Activate Now" callback,
    resolves or creates the BotClient owning the customer's Telegram identity
    and sends them their access code. Does not set
    ActivationRecord.owner_client_id/activation_status/activated_at, assign a
    BotClientSlug, or collect URL/media content — those remain later phases.
  - activation URL setup (Phase A4U): for an eligible unactivated url slug
    only, immediately after Phase A3's access-code step, prompts the
    customer for a destination URL, validates it (and trims surrounding
    whitespace only — no scheme/host/path canonicalization) with the same
    guards as the T1B self-service flow above, then asks for confirmation
    primarily via an inline "Confirm"/"Change URL" keyboard (typed YES/NO
    remains as a compatibility fallback). Both the inline callbacks and a
    repeat typed Confirm/YES are state-based idempotent: revalidated
    against DB truth (_lookup_unactivated_url_link) every time, never
    trusting session state alone, and once already confirmed a duplicate
    is a safe no-op — it never re-triggers a DB write, never resets the
    session to awaiting_code, and never loses the confirmed value. A4U
    deliberately does not intercept arbitrary post-confirmation text —
    only the explicit duplicate-confirmation keyword is special-cased, so
    unrelated text remains available to Phase A5 (not yet implemented) or
    the normal state dispatcher instead of being swallowed. The confirmed
    value is held only in the in-memory session (never written to
    RedirectLink.destination_url or any other live runtime) for Phase A5 to
    finalize. Still never touches
    ActivationRecord.owner_client_id/activation_status/activated_at or
    BotClientSlug. media slugs are untouched by this phase.

Conversation state is held in an in-memory dict, acceptable for a single
uvicorn process (no --workers flag in this deployment) and acceptable to lose
on service restart (owner-approved for T1B).

No admin functionality is reachable through this module. No webhook is
auto-registered with Telegram — that remains a manual, explicitly-approved
step (setWebhook call) after deploy.
"""
import logging
import os
import re
from collections import deque
from urllib.parse import urlparse

import httpx
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

import models
from database import get_db
# Reuses the one existing access-code generator instead of adding a second —
# bot_admin does not import this module, so this is not circular.
from bot_admin import _generate_access_code
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

async def _send_message(chat_id: int, text: str, reply_markup: dict | None = None) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        logger.error(
            "TELEGRAM_BOT_TOKEN is not configured — cannot send message to chat_id=%s",
            chat_id,
        )
        return
    url = _TELEGRAM_API_BASE.format(token=token) + "/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # Never interpolate/stringify exc — httpx's auto-generated message
        # embeds the full request URL, and Telegram's Bot API puts the token
        # directly in the URL path (no header/query param to redact instead).
        logger.error(
            "Failed to send Telegram message to chat_id=%s: HTTP %s (%s)",
            chat_id, exc.response.status_code, type(exc).__name__,
        )
    except httpx.HTTPError as exc:
        logger.error(
            "Failed to send Telegram message to chat_id=%s: %s",
            chat_id, type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# Activation Engine v1 — Phase A2 (First-Scan Telegram Entry)
#
# Builds the deep link the public slug resolver (link_public.py) redirects
# into for an unactivated url/media slug, and recognises the resulting
# /start payload. Does not create a BotClient, assign ownership, mark a
# record activated, or issue an access code — later Activation Engine
# phases own that.
# ---------------------------------------------------------------------------

_ACTIVATION_PAYLOAD_PREFIX = "activate_"
# Telegram's /start deep-link payload AND callback_data share this format —
# max 64 chars / bytes — https://core.telegram.org/bots/features#deep-linking
_START_PAYLOAD_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_ACTIVATION_PAYLOAD_BYTES = 64

# Conservative Telegram bot-username constraints: ASCII letters/digits/
# underscore only, 5-32 chars (after stripping an optional leading '@'),
# must end in "bot" (case-insensitive).
_BOT_USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{5,32}$")

_ACTIVATION_ENTRY_TEXT = (
    "✨ Your SHADZ product is ready to activate.\n\n"
    "Activate it now to connect this product to your account and unlock "
    "self-service management."
)
_ACTIVATION_CALLBACK_INVALID_TEXT = "This activation link is no longer valid."
# Single generic response for every invalid /start activation payload
# (empty/malformed/oversized token, unknown token, already-activated token,
# or a valid record whose payload can't produce safe callback_data) —
# deliberately does not distinguish which case occurred.
_ACTIVATION_INVALID_LINK_TEXT = (
    "This activation link is invalid or no longer available. Please scan "
    "your SHADZ product again or contact SHADZ support."
)
# Shown for any ordinary text sent while a chat holds an
# awaiting_activation_confirmation session — reminds the customer to use the
# button instead of falling into (or being mistaken for) Bot Client login.
_ACTIVATION_CONFIRMATION_REMINDER_TEXT = (
    'Please tap "Activate Now" to continue activating your SHADZ product.'
)

# Phase A3 continuation state — placeholder for the URL/media setup phases
# to pick up. A3 itself never collects URL/media content.
_ACTIVATION_SETUP_STATE = "awaiting_activation_setup"

# Sent once the customer's BotClient is resolved/created and an access code
# is available. Deliberately does not claim the NFC product/slug itself is
# activated yet — activation_status only transitions in a later phase.
_ACCESS_CODE_READY_TEXT = (
    "Your SHADZ client access is ready.\n\n"
    "Access code: {code}\n\n"
    "We'll continue setting up your product next."
)
# Telegram always supplies callback_query.from with a numeric id — this only
# fires on a malformed/absent update, and deliberately doesn't distinguish
# that from other rejection cases below.
_ACTIVATION_MISSING_IDENTITY_TEXT = (
    "We couldn't verify your Telegram account. Please try again from your "
    "SHADZ product link, or contact SHADZ support."
)
# Single generic response for both "matched an inactive BotClient" and
# "matched more than one BotClient" — deliberately does not reveal which
# case occurred, and never a database-failure detail.
_ACTIVATION_CLIENT_BLOCKED_TEXT = (
    "We couldn't complete this step right now. Please contact SHADZ support."
)

# ---------------------------------------------------------------------------
# Activation Engine v1 — Phase A4U (URL Content Setup)
#
# For an eligible unactivated url slug only, extends the Phase A3 session
# with two more states instead of leaving it parked at
# _ACTIVATION_SETUP_STATE. Never writes to RedirectLink.destination_url or
# any ActivationRecord lifecycle field — the confirmed URL is held only in
# the in-memory session for Phase A5 to pick up.
# ---------------------------------------------------------------------------

_ACTIVATION_URL_INPUT_STATE = "awaiting_activation_url"
_ACTIVATION_URL_CONFIRM_STATE = "awaiting_activation_url_confirmation"

_ACTIVATION_URL_PROMPT_TEXT = (
    "Now let's set up your destination.\n\n"
    "Reply with the destination URL for this product (must start with "
    "http:// or https://)."
)
_ACTIVATION_URL_INVALID_FORMAT_TEXT = (
    "That doesn't look like a valid URL — it must start with http:// or "
    "https://. Please try again."
)
# Reuses the same wording/guard as the T1B self-service flow's blocked-
# destination check (_is_blocked_destination_url) — deliberately duplicated
# as its own constant rather than shared, since the two flows are triggered
# from different states and this keeps each phase's messages independently
# editable.
_ACTIVATION_URL_BLOCKED_TEXT = (
    "This link cannot be used because it points back to SHADZ or an "
    "internal address. Please send an external public link instead."
)
# "{url}" here is the validated, trimmed destination — text.strip() only.
# Never call this "normalized": no scheme/host/path rewriting is performed,
# so the customer always sees exactly what they typed (minus surrounding
# whitespace).
_ACTIVATION_URL_CONFIRM_PROMPT_TEXT = (
    "Confirm destination:\n{url}\n\n"
    "Tap Confirm to save it, or Change URL to send a different one."
)
_ACTIVATION_URL_CONFIRM_INVALID_REPLY_TEXT = (
    "Please tap Confirm or Change URL above, or reply YES to confirm or NO "
    "to send a different URL."
)
_ACTIVATION_URL_RETRY_TEXT = "No problem — please send the destination URL again."
_ACTIVATION_URL_SAVED_TEXT = (
    "Got it. Destination saved for setup:\n{url}\n\n"
    "We'll continue setting up your product next."
)

# ---------------------------------------------------------------------------
# Activation Engine v1 — Phase A4U confirmation callbacks
#
# Narrowly-scoped callback_data prefixes for the "Confirm"/"Change URL"
# inline keyboard sent alongside _ACTIVATION_URL_CONFIRM_PROMPT_TEXT —
# deliberately distinct from _ACTIVATION_PAYLOAD_PREFIX ("activate_") so the
# webhook route can dispatch on prefix without any risk of colliding with
# Phase A2/A3's "Activate Now" callback_data.
# ---------------------------------------------------------------------------

_A4U_CONFIRM_PAYLOAD_PREFIX = "a4uconfirm_"
_A4U_CHANGE_PAYLOAD_PREFIX = "a4uchange_"


def _build_a4u_callback_payload(prefix: str, activation_token: str) -> str | None:
    """Build and validate an A4U confirmation callback_data string.

    Same format/length/charset check as _build_activation_payload (shared
    _START_PAYLOAD_RE / _MAX_ACTIVATION_PAYLOAD_BYTES), just parameterized
    on prefix so the Confirm and Change URL buttons can each get their own
    unambiguous callback_data without touching the A2/A3 payload builder.
    """
    if not activation_token:
        return None
    payload = f"{prefix}{activation_token}"
    if len(payload.encode("utf-8")) > _MAX_ACTIVATION_PAYLOAD_BYTES:
        return None
    if not _START_PAYLOAD_RE.match(payload):
        return None
    return payload


def _a4u_confirmation_markup(activation_token: str) -> dict | None:
    """Build the "Confirm" / "Change URL" inline keyboard, or None if the
    token can't produce safe callback_data for either button — callers must
    fail safe (fall back to text-only, never send a button with invalid or
    oversized callback_data)."""
    confirm_payload = _build_a4u_callback_payload(_A4U_CONFIRM_PAYLOAD_PREFIX, activation_token)
    change_payload = _build_a4u_callback_payload(_A4U_CHANGE_PAYLOAD_PREFIX, activation_token)
    if not confirm_payload or not change_payload:
        logger.error(
            "Activation token produces an invalid A4U callback_data payload — "
            "refusing to build the Confirm/Change URL buttons"
        )
        return None
    return {
        "inline_keyboard": [[
            {"text": "Confirm", "callback_data": confirm_payload},
            {"text": "Change URL", "callback_data": change_payload},
        ]]
    }


def _normalize_bot_username(raw: str) -> str | None:
    """Normalize and validate TELEGRAM_BOT_USERNAME.

    Accepts an optional single leading '@'. Returns the normalized username
    (no '@') if valid, or None if missing/invalid — callers must fail closed
    rather than build a link/button referencing a malformed or non-existent
    bot username. No production username is hardcoded here.
    """
    if not raw:
        return None
    username = raw[1:] if raw.startswith("@") else raw
    if not _BOT_USERNAME_RE.match(username):
        return None
    if not username.lower().endswith("bot"):
        return None
    return username


def _build_activation_payload(activation_token: str) -> str | None:
    """Build and validate the "activate_<token>" Telegram payload string.

    Shared by build_activation_deep_link (the /start deep link) and
    _activation_entry_markup (the "Activate Now" button's callback_data) so
    both enforce the identical format/length/charset check — neither path
    may emit a payload Telegram would reject, and tokens are never
    truncated to fit. Returns None for an empty token, a payload exceeding
    Telegram's 64-byte start-parameter/callback_data limit, or disallowed
    characters.
    """
    if not activation_token:
        return None
    payload = f"{_ACTIVATION_PAYLOAD_PREFIX}{activation_token}"
    if len(payload.encode("utf-8")) > _MAX_ACTIVATION_PAYLOAD_BYTES:
        return None
    if not _START_PAYLOAD_RE.match(payload):
        return None
    return payload


def _activation_entry_markup(activation_token: str) -> dict | None:
    """Build the "Activate Now" inline keyboard, or None if the token can't
    produce a safe callback_data payload — callers must fail safe (never
    send a button with invalid/oversized callback_data)."""
    payload = _build_activation_payload(activation_token)
    if not payload:
        logger.error(
            "Activation token produces an invalid Telegram callback_data payload — "
            "refusing to build the Activate Now button"
        )
        return None
    return {
        "inline_keyboard": [[{"text": "Activate Now", "callback_data": payload}]]
    }


def build_activation_deep_link(activation_token: str) -> str | None:
    """Build a t.me deep link that opens the bot with an activation payload.

    Fails safe (returns None) if TELEGRAM_BOT_USERNAME is missing or invalid,
    or if the resulting payload doesn't fit Telegram's allowed
    start-parameter format — callers must fall back to existing legacy
    behaviour rather than send a customer to a broken link.
    """
    username = _normalize_bot_username(os.environ.get("TELEGRAM_BOT_USERNAME", ""))
    if not username:
        logger.error(
            "TELEGRAM_BOT_USERNAME is not configured or invalid — cannot build "
            "activation deep link"
        )
        return None

    payload = _build_activation_payload(activation_token)
    if not payload:
        logger.error("Activation token produces an invalid Telegram deep-link payload")
        return None

    return f"https://t.me/{username}?start={payload}"


async def _answer_callback_query(callback_query_id: str, text: str | None = None) -> None:
    """Stop a Telegram inline-button's loading spinner.

    Fails safe (logs and returns) if TELEGRAM_BOT_TOKEN is not configured,
    matching _send_message's existing fail-safe pattern.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        logger.error(
            "TELEGRAM_BOT_TOKEN is not configured — cannot answer callback_query_id=%s",
            callback_query_id,
        )
        return
    url = _TELEGRAM_API_BASE.format(token=token) + "/answerCallbackQuery"
    payload = {"callback_query_id": callback_query_id}
    if text:
        payload["text"] = text
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Failed to answer callback_query_id=%s: HTTP %s (%s)",
            callback_query_id, exc.response.status_code, type(exc).__name__,
        )
    except httpx.HTTPError as exc:
        logger.error(
            "Failed to answer callback_query_id=%s: %s",
            callback_query_id, type(exc).__name__,
        )


def _lookup_unactivated_record(token: str, db: Session) -> "models.ActivationRecord | None":
    """Look up an eligible unactivated ActivationRecord for a token.

    Rejects a missing/empty token, an unknown token, and an already-activated
    record. Phase A3 addition: also rejects a record whose slug has since
    been archived — archiving a RedirectLink never touches its
    ActivationRecord, so an old Telegram deep link could otherwise bypass
    the archived check the public /{slug} route already enforces. Shared by
    both _handle_activation_entry and _handle_activation_callback, so the
    guard applies at first-scan entry and at the "Activate Now" callback.
    """
    if not token:
        return None
    record = (
        db.query(models.ActivationRecord)
        .filter(models.ActivationRecord.activation_token == token)
        .first()
    )
    if not record or record.activation_status != "unactivated":
        return None
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == record.slug).first()
    if not link or link.is_archived is True:
        return None
    return record


def _lookup_unactivated_url_link(token: str, db: Session) -> "models.RedirectLink | None":
    """Shared Phase A4U guard: re-validates from scratch that a token still
    resolves to an unactivated, non-archived, url-content-type slug.

    Builds on _lookup_unactivated_record (unknown/activated/archived
    checks) and adds the content_type == "url" requirement A4U needs.
    Every A4U entry point — the typed URL-input/confirmation branches in
    _handle_message and every path through _handle_a4u_confirmation_callback
    (including both duplicate-callback shortcuts) — calls this instead of
    inlining the same record+link+content_type check, so a slug that
    becomes archived, gets activated, or has its content_type changed
    between the confirmation prompt and any later message/callback is
    caught uniformly, never trusting session state alone.
    """
    record = _lookup_unactivated_record(token, db)
    if not record:
        return None
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == record.slug).first()
    if not link or link.content_type != "url":
        return None
    return link


async def _handle_activation_entry(chat_id: int, payload: str, db: Session) -> None:
    """Handle a /start deep-link payload carrying an activation token.

    Only recognises the payload and shows the Phase A2 entry message — does
    not create a BotClient, claim ownership, mark the record activated, or
    issue an access code. A valid unactivated token gets its own
    activation-specific session state — it is never placed into the
    ordinary Bot Client access-code login flow. An unknown, already-
    activated, malformed, or otherwise unusable token clears any stale
    session and shows one generic activation-invalid message, without
    revealing which case occurred or falling back to the login prompt.
    """
    token = payload[len(_ACTIVATION_PAYLOAD_PREFIX):]
    record = _lookup_unactivated_record(token, db)
    markup = _activation_entry_markup(token) if record else None

    if not record or markup is None:
        _SESSIONS.pop(chat_id, None)
        await _send_message(chat_id, _ACTIVATION_INVALID_LINK_TEXT)
        return

    _SESSIONS[chat_id] = {"state": "awaiting_activation_confirmation", "activation_token": token}
    await _send_message(chat_id, _ACTIVATION_ENTRY_TEXT, reply_markup=markup)


def _default_bot_client_name(
    first_name: str | None, last_name: str | None, username: str | None, telegram_user_id: str
) -> str:
    """Build a client_name for a newly self-service-created BotClient.

    Order: "first_name last_name" > "@username" > "Telegram user <id>".
    Never used to rename an existing client — only at creation time.
    """
    name_parts = [p.strip() for p in (first_name, last_name) if p and p.strip()]
    if name_parts:
        return " ".join(name_parts)
    if username and username.strip():
        return f"@{username.strip()}"
    return f"Telegram user {telegram_user_id}"


def _resolve_or_create_bot_client_for_telegram(
    db: Session,
    telegram_user_id: str,
    telegram_username: str | None,
    first_name: str | None,
    last_name: str | None,
) -> tuple[str, "models.BotClient | None"]:
    """Resolve the BotClient owning this Telegram identity, or create one.

    Identity is keyed strictly on the numeric Telegram user_id — username,
    first_name, and last_name are profile fields only and are never used for
    matching (usernames can change; they are not identity).

    Returns (status, client):
      - ("reused", client): exactly one existing active match — returned
        untouched, access code never regenerated, profile fields never
        rewritten even if the Telegram profile changed since last time.
      - ("created", client): no existing match — a new active BotClient is
        staged (add/flush, not committed) with an access code from the one
        existing bot_admin generator.
      - ("inactive", None): exactly one existing match and it is inactive —
        never reactivated, and no replacement client is created.
      - ("ambiguous", None): more than one existing match regardless of
        active state — fails closed, creates nothing.

    Uses add()/flush() only; the caller owns commit()/rollback().
    """
    matches = (
        db.query(models.BotClient)
        .filter(models.BotClient.telegram_user_id == telegram_user_id)
        .all()
    )
    if len(matches) > 1:
        return "ambiguous", None
    if len(matches) == 1:
        existing = matches[0]
        if not existing.is_active:
            return "inactive", None
        return "reused", existing

    client = models.BotClient(
        client_name=_default_bot_client_name(first_name, last_name, telegram_username, telegram_user_id),
        access_code=_generate_access_code(db),
        telegram_user_id=telegram_user_id,
        telegram_username=telegram_username,
        is_active=True,
    )
    db.add(client)
    db.flush()
    return "created", client


async def _handle_activation_callback(callback_query: dict, db: Session) -> None:
    """Handle the "Activate Now" inline-button press.

    Always answers the callback query at most once, and only if Telegram
    supplied a callback_query_id — an update missing one is never
    acknowledged (there is nothing to acknowledge), and this never crashes
    on a malformed update (non-dict callback_query, or a missing/malformed
    id/data/message/chat). Validates the inbound callback_data through the
    same shared _build_activation_payload validator used to generate
    outbound deep links/buttons BEFORE any database lookup, so malformed,
    empty, invalid-character, or oversized activation payloads never reach
    the DB. Re-validates the token/record from scratch (never trusts state
    from when the entry message was sent).

    Phase A3: once the token/record are re-validated, resolves or creates
    the BotClient for the customer's Telegram identity
    (_resolve_or_create_bot_client_for_telegram) and sends the access code.
    Still does not touch activation_status, activated_at,
    ActivationRecord.owner_client_id, or BotClientSlug — those remain later
    phases. A missing/malformed numeric Telegram user id, or a resolution
    that comes back inactive/ambiguous/failed, creates and modifies nothing
    and replies with one generic message. Any callback_data that isn't a
    recognised activation payload is answered and otherwise ignored.

    Phase A4U: for a url slug only, immediately follows the access-code
    message with the URL-input prompt and moves the session into
    _ACTIVATION_URL_INPUT_STATE instead of the generic _ACTIVATION_SETUP_STATE
    placeholder. media slugs are unaffected — they still land in
    _ACTIVATION_SETUP_STATE with no follow-up message.
    """
    if not isinstance(callback_query, dict):
        return

    callback_query_id = callback_query.get("id")
    data = callback_query.get("data")
    if not isinstance(data, str):
        data = ""

    if not data.startswith(_ACTIVATION_PAYLOAD_PREFIX):
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    token = data[len(_ACTIVATION_PAYLOAD_PREFIX):]

    # Validate the payload format/length/charset BEFORE the DB lookup —
    # the same shared validator outbound generation uses, so inbound data
    # can never bypass a check the outbound path enforces.
    if _build_activation_payload(token) is None:
        if callback_query_id:
            await _answer_callback_query(callback_query_id, text=_ACTIVATION_CALLBACK_INVALID_TEXT)
        return

    record = _lookup_unactivated_record(token, db)

    if not record:
        if callback_query_id:
            await _answer_callback_query(callback_query_id, text=_ACTIVATION_CALLBACK_INVALID_TEXT)
        return

    if callback_query_id:
        await _answer_callback_query(callback_query_id)

    message = callback_query.get("message")
    chat = message.get("chat") if isinstance(message, dict) else None
    chat_id = chat.get("id") if isinstance(chat, dict) else None

    from_user = callback_query.get("from")
    telegram_user_id = from_user.get("id") if isinstance(from_user, dict) else None
    if (
        not isinstance(telegram_user_id, int)
        or isinstance(telegram_user_id, bool)
        or telegram_user_id <= 0
    ):
        if chat_id is not None:
            await _send_message(chat_id, _ACTIVATION_MISSING_IDENTITY_TEXT)
        return

    # Re-fetch the slug's content_type fresh — _lookup_unactivated_record
    # already proved the RedirectLink exists and isn't archived above.
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == record.slug).first()
    if not link:
        if chat_id is not None:
            await _send_message(chat_id, _ACTIVATION_MISSING_IDENTITY_TEXT)
        return

    try:
        status, client = _resolve_or_create_bot_client_for_telegram(
            db,
            telegram_user_id=str(telegram_user_id),
            telegram_username=from_user.get("username"),
            first_name=from_user.get("first_name"),
            last_name=from_user.get("last_name"),
        )
    except Exception:
        db.rollback()
        logger.exception("Failed to resolve/create BotClient for activation token")
        if chat_id is not None:
            _SESSIONS.pop(chat_id, None)
            await _send_message(chat_id, _ACTIVATION_CLIENT_BLOCKED_TEXT)
        return

    if status in ("inactive", "ambiguous"):
        db.rollback()
        if chat_id is not None:
            _SESSIONS.pop(chat_id, None)
            await _send_message(chat_id, _ACTIVATION_CLIENT_BLOCKED_TEXT)
        return

    # A reused client is already committed — only a newly created client has
    # anything pending to persist.
    if status == "created":
        try:
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to commit BotClient resolution for activation token")
            if chat_id is not None:
                _SESSIONS.pop(chat_id, None)
                await _send_message(chat_id, _ACTIVATION_CLIENT_BLOCKED_TEXT)
            return

    if chat_id is not None:
        if link.content_type == "url":
            _SESSIONS[chat_id] = {
                "state": _ACTIVATION_URL_INPUT_STATE,
                "activation_token": token,
                "bot_client_id": client.id,
                "content_type": link.content_type,
            }
            await _send_message(chat_id, _ACCESS_CODE_READY_TEXT.format(code=client.access_code))
            await _send_message(chat_id, _ACTIVATION_URL_PROMPT_TEXT)
        else:
            _SESSIONS[chat_id] = {
                "state": _ACTIVATION_SETUP_STATE,
                "activation_token": token,
                "bot_client_id": client.id,
                "content_type": link.content_type,
            }
            await _send_message(chat_id, _ACCESS_CODE_READY_TEXT.format(code=client.access_code))


async def _handle_a4u_confirmation_callback(callback_query: dict, db: Session) -> None:
    """Handle the Phase A4U "Confirm" / "Change URL" inline-button press.

    Distinct callback_data prefixes (_A4U_CONFIRM_PAYLOAD_PREFIX /
    _A4U_CHANGE_PAYLOAD_PREFIX) keep this entirely separate from Phase
    A2/A3's "activate_" callback dispatch — the webhook route routes here by
    prefix before ever calling _handle_activation_callback, so existing
    A2/A3/T1B behaviour is untouched.

    Always answers the callback query at most once, and only if Telegram
    supplied a callback_query_id. Never crashes on a malformed update
    (non-dict callback_query, missing id/data/message/chat).

    Every path — the two duplicate-safety shortcuts AND the ordinary
    confirm/change path — first revalidates the token against DB truth via
    the shared _lookup_unactivated_url_link(token, db): the linked
    ActivationRecord must still be unactivated, the RedirectLink must still
    exist and not be archived, and its content_type must still be "url".
    This is re-checked from scratch on every callback, so a slug that gets
    archived, activated, or switched to media between the confirmation
    prompt and any later callback (including a duplicate tap) is caught —
    duplicate delivery never bypasses this by trusting session state alone.

    Duplicate-safety (state-based, not update_id-based — this must hold
    even if Telegram redelivers the tap under a different update_id), only
    reached once the DB-truth check above has already passed:
      - A repeat Confirm tap once the session already advanced past
        confirmation (same token, state == _ACTIVATION_SETUP_STATE, a
        confirmed_destination_url already stored) is a no-op: answers the
        callback and returns, without touching the DB, the session state,
        or the stored value, and without sending a message.
      - A repeat Change URL tap once the session already returned to URL
        input (same token, state == _ACTIVATION_URL_INPUT_STATE) is
        likewise a no-op.
      - Anything else requires the session to currently be in
        _ACTIVATION_URL_CONFIRM_STATE for this exact token — a
        token-mismatched/cross-chat/stale/missing session fails closed
        (clears the session, answers with the generic invalid-link
        callback text) exactly like Phase A2/A3's existing guards. The
        DB-truth check above already covers archived/already-
        activated/wrong-type rejection for this branch too.

    Confirm: stores the validated, trimmed pending_url as
    confirmed_destination_url in the in-memory session only, moves the
    session to the existing _ACTIVATION_SETUP_STATE placeholder for Phase
    A5 to pick up. Never writes to RedirectLink.destination_url, never
    touches ActivationRecord.owner_client_id/activation_status/activated_at,
    never assigns a BotClientSlug.

    Change URL: clears pending_url and any confirmed_destination_url, and
    returns the session to _ACTIVATION_URL_INPUT_STATE.
    """
    if not isinstance(callback_query, dict):
        return

    callback_query_id = callback_query.get("id")
    data = callback_query.get("data")
    if not isinstance(data, str):
        data = ""

    if data.startswith(_A4U_CONFIRM_PAYLOAD_PREFIX):
        prefix, action = _A4U_CONFIRM_PAYLOAD_PREFIX, "confirm"
    elif data.startswith(_A4U_CHANGE_PAYLOAD_PREFIX):
        prefix, action = _A4U_CHANGE_PAYLOAD_PREFIX, "change"
    else:
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    token = data[len(prefix):]

    # Validate the payload format/length/charset BEFORE any DB/session
    # lookup — same shared-shape check the outbound button builder enforces.
    if _build_a4u_callback_payload(prefix, token) is None:
        if callback_query_id:
            await _answer_callback_query(callback_query_id, text=_ACTIVATION_CALLBACK_INVALID_TEXT)
        return

    message = callback_query.get("message")
    chat = message.get("chat") if isinstance(message, dict) else None
    chat_id = chat.get("id") if isinstance(chat, dict) else None
    session = _SESSIONS.get(chat_id) if chat_id is not None else None
    session_matches_token = session is not None and session.get("activation_token") == token

    # DB-truth check FIRST — applies uniformly to both duplicate shortcuts
    # below and the ordinary confirm/change path. Never trust session state
    # alone: a stale/duplicate tap must fail closed just like a fresh one
    # if the slug has since been archived, activated, or changed type.
    link = _lookup_unactivated_url_link(token, db)
    if link is None:
        if callback_query_id:
            await _answer_callback_query(callback_query_id, text=_ACTIVATION_CALLBACK_INVALID_TEXT)
        if chat_id is not None:
            _SESSIONS.pop(chat_id, None)
        return

    # Duplicate-safety: a repeat Confirm tap after the session already
    # advanced past confirmation (same token) is a no-op — never re-answer
    # with an error, never touch the DB, never reset/lose the confirmed URL.
    if (
        action == "confirm"
        and session_matches_token
        and session.get("state") == _ACTIVATION_SETUP_STATE
        and "confirmed_destination_url" in session
    ):
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    # Duplicate-safety: a repeat Change URL tap after the session already
    # returned to URL input (same token) is likewise a no-op.
    if (
        action == "change"
        and session_matches_token
        and session.get("state") == _ACTIVATION_URL_INPUT_STATE
    ):
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    valid_session = session_matches_token and session.get("state") == _ACTIVATION_URL_CONFIRM_STATE
    if not valid_session:
        if callback_query_id:
            await _answer_callback_query(callback_query_id, text=_ACTIVATION_CALLBACK_INVALID_TEXT)
        if chat_id is not None:
            _SESSIONS.pop(chat_id, None)
        return

    if callback_query_id:
        await _answer_callback_query(callback_query_id)

    if action == "confirm":
        session["confirmed_destination_url"] = session.get("pending_url")
        session.pop("pending_url", None)
        session["state"] = _ACTIVATION_SETUP_STATE
        _SESSIONS[chat_id] = session
        await _send_message(
            chat_id, _ACTIVATION_URL_SAVED_TEXT.format(url=session["confirmed_destination_url"])
        )
        return

    # action == "change"
    session.pop("pending_url", None)
    session.pop("confirmed_destination_url", None)
    session["state"] = _ACTIVATION_URL_INPUT_STATE
    _SESSIONS[chat_id] = session
    await _send_message(chat_id, _ACTIVATION_URL_RETRY_TEXT)


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
        try:
            get_file_resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            # exc's auto-generated message embeds the token-bearing URL — never
            # let it reach a caller's logger.exception(). from None suppresses
            # exception chaining so the original is not printed in a traceback.
            raise RuntimeError(
                f"getFile request failed: HTTP {exc.response.status_code}"
            ) from None
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
        try:
            file_resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"file download failed: HTTP {exc.response.status_code}"
            ) from None
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

    lowered = text.lower()
    if lowered in ("/start", "start"):
        _SESSIONS[chat_id] = {"state": "awaiting_code"}
        await _send_message(chat_id, "Welcome to SHADZ. Please enter your access code.")
        return

    if lowered.startswith("/start "):
        payload = text[len("/start "):].strip()
        if payload.startswith(_ACTIVATION_PAYLOAD_PREFIX):
            await _handle_activation_entry(chat_id, payload, db)
        else:
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

    if state == "awaiting_activation_confirmation":
        # Ordinary text here must never fall into Bot Client login — the
        # session (and its activation_token) is preserved untouched, and the
        # text is never treated as an access code.
        await _send_message(chat_id, _ACTIVATION_CONFIRMATION_REMINDER_TEXT)
        return

    if (
        state == _ACTIVATION_SETUP_STATE
        and "confirmed_destination_url" in session
        and text.lower() in ("yes", "y", "confirm")
    ):
        # Duplicate-safety: a stray repeat of the confirmation keyword after
        # the session already advanced past confirmation is a safe no-op —
        # no DB write, no message, no session change, confirmed URL kept.
        # Deliberately narrow: this must NOT become a catch-all for every
        # message in this state — unrelated text is intentionally left
        # unhandled here so it remains available to Phase A5 (not yet
        # implemented) or the normal state dispatcher below, instead of
        # being swallowed by an A4U-specific branch that would otherwise
        # block all future text handling indefinitely.
        return

    if state in (_ACTIVATION_URL_INPUT_STATE, _ACTIVATION_URL_CONFIRM_STATE):
        # Re-validate the activation session from scratch on every message —
        # never trust that the token/record are still eligible just because
        # the session reached this state earlier (archived/activated since,
        # or a forged/stale session). Shared with the A4U callback handler
        # via _lookup_unactivated_url_link.
        token = session.get("activation_token")
        link = _lookup_unactivated_url_link(token, db)
        if link is None:
            _SESSIONS.pop(chat_id, None)
            await _send_message(chat_id, _ACTIVATION_INVALID_LINK_TEXT)
            return

        if state == _ACTIVATION_URL_INPUT_STATE:
            if not (text.startswith("http://") or text.startswith("https://")):
                await _send_message(chat_id, _ACTIVATION_URL_INVALID_FORMAT_TEXT)
                return
            if _is_blocked_destination_url(text):
                await _send_message(chat_id, _ACTIVATION_URL_BLOCKED_TEXT)
                return

            # Validated, trimmed URL — text.strip() only. No scheme/host/
            # path canonicalization is performed, so the customer's intent
            # is never rewritten.
            trimmed_url = text.strip()
            session["pending_url"] = trimmed_url
            session["state"] = _ACTIVATION_URL_CONFIRM_STATE
            _SESSIONS[chat_id] = session
            markup = _a4u_confirmation_markup(token)
            await _send_message(
                chat_id,
                _ACTIVATION_URL_CONFIRM_PROMPT_TEXT.format(url=trimmed_url),
                reply_markup=markup,
            )
            return

        # state == _ACTIVATION_URL_CONFIRM_STATE — typed YES/NO fallback,
        # kept for compatibility alongside the inline Confirm/Change URL
        # buttons sent above. Same duplicate-safety contract as the
        # callback handler: by the time a message reaches this branch, the
        # session is still in _ACTIVATION_URL_CONFIRM_STATE (a prior
        # successful confirm/change already moved it elsewhere, so a stray
        # duplicate typed reply here is guaranteed to be genuinely pending,
        # not a re-processed duplicate).
        answer = text.lower()
        if answer in ("yes", "y", "confirm"):
            session["confirmed_destination_url"] = session.get("pending_url")
            session.pop("pending_url", None)
            session["state"] = _ACTIVATION_SETUP_STATE
            _SESSIONS[chat_id] = session
            await _send_message(
                chat_id,
                _ACTIVATION_URL_SAVED_TEXT.format(url=session["confirmed_destination_url"]),
            )
            return
        if answer in ("no", "n", "change", "retry", "cancel"):
            session.pop("pending_url", None)
            session.pop("confirmed_destination_url", None)
            session["state"] = _ACTIVATION_URL_INPUT_STATE
            _SESSIONS[chat_id] = session
            await _send_message(chat_id, _ACTIVATION_URL_RETRY_TEXT)
            return
        await _send_message(chat_id, _ACTIVATION_URL_CONFIRM_INVALID_REPLY_TEXT)
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
        callback_query = body.get("callback_query")
        if not message and not callback_query:
            return {"ok": True}

        update_id = body.get("update_id")
        if update_id is not None:
            if update_id in _SEEN_UPDATE_IDS:
                return {"ok": True}
            _SEEN_UPDATE_IDS.append(update_id)

        if callback_query is not None:
            try:
                cq_data = callback_query.get("data") if isinstance(callback_query, dict) else None
                if isinstance(cq_data, str) and (
                    cq_data.startswith(_A4U_CONFIRM_PAYLOAD_PREFIX)
                    or cq_data.startswith(_A4U_CHANGE_PAYLOAD_PREFIX)
                ):
                    # Distinct prefix dispatch — never touches the A2/A3
                    # "activate_" callback path below.
                    await _handle_a4u_confirmation_callback(callback_query, db)
                else:
                    await _handle_activation_callback(callback_query, db)
            except Exception:
                logger.exception("Unhandled error processing callback update_id=%s", update_id)
            return {"ok": True}

        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            return {"ok": True}

        text = message.get("text") or ""
        from_user = message.get("from") or {}

        try:
            await _handle_message(chat_id, text, from_user, db, message)
        except Exception:
            logger.exception("Unhandled error processing update_id=%s chat_id=%s", update_id, chat_id)

        return {"ok": True}
