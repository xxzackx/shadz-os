"""Telegram Bot Runtime — Phase T1B + T1C + Activation Engine v1 Phase A2 + A3
+ Hotfix H1F (Multilingual Activation Flow).

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
    session to awaiting_code, and never loses the confirmed value. A
    temporary post-confirmation placeholder (clearly marked in
    _handle_message, meant to be replaced outright by Phase A5) answers
    ANY further message — explicit duplicate confirmation text or
    otherwise — with a brief reply while leaving the session and
    confirmed_destination_url completely untouched, so nothing ever falls
    into the generic "Unknown/expired state" reset and discards the
    confirmed value. The confirmed value is held only in the in-memory
    session (never written to RedirectLink.destination_url or any other
    live runtime) for Phase A5 to finalize. Still never touches
    ActivationRecord.owner_client_id/activation_status/activated_at or
    BotClientSlug.
  - activation media setup (Phase A4M): mirrors A4U for an eligible
    unactivated media slug instead of a url slug. Immediately after Phase
    A3's access-code step, prompts for a photo/document/video/GIF using the
    same extraction/mime-allowlist/size guards as the existing T1C
    replacement-media flow — but performs ZERO persistent media storage.
    It never calls _download_telegram_file, never calls _upload_bytes_to_r2,
    and never creates a MediaAsset row. Only Telegram's own message metadata
    (file_id, resolved media_type, mime_type, filename, reported file_size)
    is validated and held as a plain dict, session["pending_activation_media"],
    entirely in the in-memory session — never a DB write. Confirmation is
    inline-button-only ("Confirm"/"Change Media" — no typed fallback, unlike
    A4U's YES/NO). Every A4M entry point (message and callback) revalidates
    the token/record/link from scratch via _lookup_unactivated_media_link,
    exactly like A4U's _lookup_unactivated_url_link. Confirm moves the
    pending dict to session["confirmed_activation_media"] (still in-memory
    only) and lands in the same _ACTIVATION_SETUP_STATE placeholder A4U
    uses. Change Media discards the pending dict and returns to media
    input — there is nothing to clean up in R2 or the DB because nothing
    was ever written there. Phase A5 owns the actual
    download/upload/MediaAsset-creation/slug-attachment sequence. Still
    never touches ActivationRecord.owner_client_id/activation_status/
    activated_at or BotClientSlug.
  - activation finalization (Phase A5): runs inline, in the same request,
    immediately after A4U/A4M's own Confirm step lands the session in
    _ACTIVATION_SETUP_STATE with confirmed content — no second button, no
    extra tap. A4U/A4M's Confirm handlers themselves are untouched (still
    only ever stash validated content into the session); the webhook route
    and the A4U typed-YES compatibility path both call
    _finalize_activation_confirmation immediately afterward. It re-validates
    every authoritative record from scratch, creates or reuses the
    BotClientSlug assignment the activated BotClient needs to immediately
    manage the slug (failing closed if the slug already belongs to a
    different client), and performs the destination-URL write or the full
    Telegram-download/R2-upload/MediaAsset/SlugMedia sequence together with
    ActivationRecord.owner_client_id/activation_status/activated_at in one
    transaction — committing all of it together or rolling all of it back.
    The activation_status transition itself is an atomic conditional UPDATE
    (WHERE activation_status = 'unactivated'), so two concurrent
    finalizations for the same token can never both persist: the loser's
    entire transaction is rolled back, untouched, as a silent no-op.
  - multilingual activation flow (Hotfix H1F): inserts a language-selector
    step between the /start deep link and Phase A2's entry message —
    _handle_activation_entry now shows a 4-language picker
    (activation_i18n.SUPPORTED_LANGUAGES) instead of the entry text
    directly; the entry message/button only appear once a language is
    chosen (_handle_activation_language_callback). The chosen language is
    stored on the SAME in-memory session dict every later phase already
    carries (session["language"]) — no new persistence layer, no DB
    schema change. Every activation message/button from that point on
    (entry, access-code-ready, url/media prompts and confirmations,
    finalize outcomes) is looked up via activation_i18n.text()/button()
    using that stored language, falling back to English for a missing or
    unrecognised value (e.g. a session that predates this deploy).
    Ownership, token validation, URL/media activation logic, Telegram
    username refresh, URL normalization, and every other Activation
    Engine behavior are unchanged — only which language the customer-
    facing text renders in.

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
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

import activation_i18n
import models
from database import get_db
# Reuses the one existing access-code generator instead of adding a second —
# bot_admin does not import this module, so this is not circular.
from bot_admin import _generate_access_code
# UI3D-C1 reuses the existing activation-token generator instead of adding a
# second one — link_admin does not import this module, so this is not
# circular. models.create_activation_record_for_slug (also reused below)
# is already a plain module-level function, not tied to link_admin.
from link_admin import _generate_activation_token
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


def _pop_stale_session(chat_id: int | None, expected_session: dict | None) -> None:
    """Clear _SESSIONS[chat_id] only if it's still the exact stale session
    object the caller read earlier — guards against a genuinely concurrent
    interleaving where something else replaces the session in the gap
    between this caller's read and its cleanup. See
    _pop_session_unless_already_activated for the sequential case (the far
    more common one), which this alone does not cover.
    """
    if chat_id is not None and _SESSIONS.get(chat_id) is expected_session:
        _SESSIONS.pop(chat_id, None)


def _pop_session_unless_already_activated(
    chat_id: int | None, expected_session: dict | None, token: str, db: Session
) -> None:
    """Clear a session on a genuinely invalid/expired activation token —
    but never when a winner has already moved this exact chat's session
    past this activation flow.

    A DB-truth lookup for THIS token can fail because its own
    ActivationRecord is already "activated" in two different situations,
    and only one of them should skip the pop:
      - A Phase A5 finalize for this exact token already succeeded AND
        replaced this chat's session with the winner's normal
        authenticated state (no longer carrying this activation_token at
        all) — sequentially (a customer double-tapping Confirm: the first
        tap activates and resets the session, then the second tap's
        callback re-validates and finds the record no longer
        "unactivated") or via a genuine concurrent race. Here the current
        session must be left alone.
      - The record became activated by some other means entirely, while
        THIS chat's own session was never touched by anyone and still
        looks exactly like the same unfinished activation flow (still
        carries this activation_token). Here there is no winner state to
        protect, and the existing fail-closed behaviour (clear the stale
        session) is correct and unchanged.
    The current session is re-read fresh (not the possibly-stale
    `expected_session` the caller captured earlier) specifically to tell
    these two apart.
    """
    status = (
        db.query(models.ActivationRecord.activation_status)
        .filter(models.ActivationRecord.activation_token == token)
        .scalar()
        if token else None
    )
    if status == "activated":
        current = _SESSIONS.get(chat_id) if chat_id is not None else None
        if current is not None and current.get("activation_token") != token:
            return
    _pop_stale_session(chat_id, expected_session)


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
    "Reply with the destination URL for this product — a domain such as "
    "example.com or a full http:// / https:// URL."
)
_ACTIVATION_URL_INVALID_FORMAT_TEXT = (
    "That doesn't look like a valid web URL. Send a domain such as "
    "example.com or a full http:// / https:// URL, then try again."
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
# "{url}" here is the validated, normalized destination (Hotfix H1D):
# trimmed, with "https://" prepended when the customer didn't supply a
# scheme. An explicitly supplied http:// or https:// is preserved
# verbatim — no other host/path rewriting is performed.
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


def _a4u_confirmation_markup(
    activation_token: str, lang: str = activation_i18n.DEFAULT_LANGUAGE
) -> dict | None:
    """Build the "Confirm" / "Change URL" inline keyboard, or None if the
    token can't produce safe callback_data for either button — callers must
    fail safe (fall back to text-only, never send a button with invalid or
    oversized callback_data). H1F: button labels are localized to lang
    (defaults to English, so every pre-H1F caller/test keeps working
    unchanged)."""
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
            {"text": activation_i18n.button("CONFIRM", lang), "callback_data": confirm_payload},
            {"text": activation_i18n.button("CHANGE_URL", lang), "callback_data": change_payload},
        ]]
    }


# ---------------------------------------------------------------------------
# Activation Engine v1 — Phase A4M (Media Content Setup)
#
# Mirrors the A4U constants/helpers above for an eligible unactivated media
# slug instead of a url slug. Distinct callback_data prefixes from both
# _ACTIVATION_PAYLOAD_PREFIX and the A4U prefixes so the webhook route can
# dispatch on prefix without any collision risk.
# ---------------------------------------------------------------------------

_ACTIVATION_MEDIA_INPUT_STATE = "awaiting_activation_media"
_ACTIVATION_MEDIA_CONFIRM_STATE = "awaiting_activation_media_confirmation"

_A4M_CONFIRM_PAYLOAD_PREFIX = "a4mconfirm_"
_A4M_CHANGE_PAYLOAD_PREFIX = "a4mchange_"

_ACTIVATION_MEDIA_PROMPT_TEXT = (
    "Now let's set up your media.\n\n"
    "Send a photo, document, video, or GIF for this product."
)
_ACTIVATION_MEDIA_UNSUPPORTED_TEXT = (
    "Please send a photo, document, video, or GIF to set up the media — "
    "plain text isn't accepted."
)
_ACTIVATION_MEDIA_UNSUPPORTED_TYPE_TEXT = (
    "That file type ({mime}) isn't supported. "
    "Supported: JPEG/PNG/WEBP images, MP4/QuickTime/WEBM video, GIF."
)
_ACTIVATION_MEDIA_TOO_LARGE_TEXT = (
    "That file is too large ({size} MB). Max supported size is {max} MB."
)
# "{name}" is the filename metadata only — never a display/marketing label.
# No download happens before this prompt, so this is Telegram-reported
# metadata (or the same _default_filename fallback T1C uses), not a
# confirmed/verified value.
_ACTIVATION_MEDIA_CONFIRM_PROMPT_TEXT = (
    "Confirm media:\n{name}\n\n"
    "Tap Confirm to save it, or Change Media to send a different file."
)
_ACTIVATION_MEDIA_CONFIRM_REMINDER_TEXT = (
    'Please tap "Confirm" or "Change Media" above to continue.'
)
_ACTIVATION_MEDIA_RETRY_TEXT = "No problem — please send the media again."
_ACTIVATION_MEDIA_SAVED_TEXT = (
    "Got it. Media saved for setup.\n\n"
    "We'll continue setting up your product next."
)


def _a4m_confirmation_markup(
    activation_token: str, lang: str = activation_i18n.DEFAULT_LANGUAGE
) -> dict | None:
    """Build the "Confirm" / "Change Media" inline keyboard, or None if the
    token can't produce safe callback_data for either button — mirrors
    _a4u_confirmation_markup, reusing the same generic (prefix-agnostic
    despite its name) _build_a4u_callback_payload validator with the
    A4M-specific prefixes. H1F: button labels are localized to lang."""
    confirm_payload = _build_a4u_callback_payload(_A4M_CONFIRM_PAYLOAD_PREFIX, activation_token)
    change_payload = _build_a4u_callback_payload(_A4M_CHANGE_PAYLOAD_PREFIX, activation_token)
    if not confirm_payload or not change_payload:
        logger.error(
            "Activation token produces an invalid A4M callback_data payload — "
            "refusing to build the Confirm/Change Media buttons"
        )
        return None
    return {
        "inline_keyboard": [[
            {"text": activation_i18n.button("CONFIRM", lang), "callback_data": confirm_payload},
            {"text": activation_i18n.button("CHANGE_MEDIA", lang), "callback_data": change_payload},
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


def _activation_entry_markup(
    activation_token: str, lang: str = activation_i18n.DEFAULT_LANGUAGE
) -> dict | None:
    """Build the "Activate Now" inline keyboard, or None if the token can't
    produce a safe callback_data payload — callers must fail safe (never
    send a button with invalid/oversized callback_data). H1F: the button
    label is localized to lang (defaults to English, so every pre-H1F
    caller/test keeps working unchanged)."""
    payload = _build_activation_payload(activation_token)
    if not payload:
        logger.error(
            "Activation token produces an invalid Telegram callback_data payload — "
            "refusing to build the Activate Now button"
        )
        return None
    return {
        "inline_keyboard": [[
            {"text": activation_i18n.button("ACTIVATE_NOW", lang), "callback_data": payload}
        ]]
    }


# ---------------------------------------------------------------------------
# Activation Engine v1 Hotfix H1F — Multilingual Activation Flow
#
# Inserts a language-selection step between the /start deep link and the
# existing Phase A2 entry message: _handle_activation_entry now shows a
# language picker instead of the entry text directly, and the chosen
# language is stored on the SAME in-memory session dict Phase A2/A3/A4U/A4M
# already carry (session["language"]) — no new persistence mechanism, no DB
# schema change. Every downstream activation message/button (entry text,
# access-code-ready, url/media prompts and confirmations, finalize
# messages) is looked up through activation_i18n.text()/button() using that
# stored language, falling back to English if unset (e.g. a session that
# predates this deploy) or unrecognised. A distinct callback_data prefix
# ("actlang_") keeps language-selection callbacks from ever colliding with
# the existing "activate_"/"a4uconfirm_"/etc. prefixes the webhook route
# already dispatches on.
# ---------------------------------------------------------------------------

_ACTIVATION_LANGUAGE_SELECT_STATE = "awaiting_activation_language"
_ACTIVATION_LANG_PAYLOAD_PREFIX = "actlang_"


def _build_activation_lang_payload(lang: str, activation_token: str) -> str | None:
    """Build and validate an "actlang_<lang>_<token>" callback_data string.

    Same format/length/charset check _build_activation_payload uses (shared
    _START_PAYLOAD_RE / _MAX_ACTIVATION_PAYLOAD_BYTES), plus a check that
    lang is one of the exact 4 supported codes. Real activation tokens are
    fixed-length (secrets.token_urlsafe(24) -> 32 chars), leaving ample
    headroom under Telegram's 64-byte callback_data limit even with this
    longer prefix.
    """
    if lang not in activation_i18n.LANGUAGE_CODES or not activation_token:
        return None
    payload = f"{_ACTIVATION_LANG_PAYLOAD_PREFIX}{lang}_{activation_token}"
    if len(payload.encode("utf-8")) > _MAX_ACTIVATION_PAYLOAD_BYTES:
        return None
    if not _START_PAYLOAD_RE.match(payload):
        return None
    return payload


def _activation_language_markup(activation_token: str) -> dict | None:
    """Build the language-selector inline keyboard (one button per
    supported language, 2 per row — a clean 2x2 grid for the 4 supported
    languages), or None if the token can't produce safe callback_data for
    every button — fails safe exactly like the other activation markup
    builders (never sends a partial keyboard)."""
    rows: list[list[dict]] = []
    row: list[dict] = []
    for code, label in activation_i18n.SUPPORTED_LANGUAGES:
        payload = _build_activation_lang_payload(code, activation_token)
        if payload is None:
            logger.error(
                "Activation token produces an invalid language-select callback_data "
                "payload — refusing to build the language selector"
            )
            return None
        row.append({"text": label, "callback_data": payload})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return {"inline_keyboard": rows}


def _session_language(chat_id: int, activation_token: str) -> str:
    """Read session["language"] for chat_id, only if that session still
    carries the same activation_token — otherwise (no session, mismatched
    token, missing/unrecognised language) falls back to English. Never
    trusts a stale/unrelated session's language for a different token."""
    session = _SESSIONS.get(chat_id)
    if session and session.get("activation_token") == activation_token:
        lang = session.get("language")
        if lang in activation_i18n.LANGUAGE_CODES:
            return lang
    return activation_i18n.DEFAULT_LANGUAGE


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


def _lookup_unactivated_media_link(token: str, db: Session) -> "models.RedirectLink | None":
    """Shared Phase A4M guard: re-validates from scratch that a token still
    resolves to an unactivated, non-archived, media-content-type slug.

    Mirrors _lookup_unactivated_url_link for the media flow — every A4M
    entry point (the media-input/confirmation branches in _handle_message
    and every path through _handle_a4m_confirmation_callback) calls this
    instead of inlining the same record+link+content_type check.
    """
    record = _lookup_unactivated_record(token, db)
    if not record:
        return None
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == record.slug).first()
    if not link or link.content_type != "media":
        return None
    return link


async def _handle_activation_entry(chat_id: int, payload: str, db: Session) -> None:
    """Handle a /start deep-link payload carrying an activation token.

    H1F: only recognises the payload and shows the language selector — does
    not yet show the Phase A2 entry message, create a BotClient, claim
    ownership, mark the record activated, or issue an access code. A valid
    unactivated token gets its own activation-specific session state — it
    is never placed into the ordinary Bot Client access-code login flow.
    An unknown, already-activated, malformed, or otherwise unusable token
    clears any stale session and shows one generic activation-invalid
    message (in English — no language has been chosen yet), without
    revealing which case occurred or falling back to the login prompt. The
    Phase A2 entry message itself is now sent by
    _handle_activation_language_callback once the customer picks a
    language.
    """
    token = payload[len(_ACTIVATION_PAYLOAD_PREFIX):]
    record = _lookup_unactivated_record(token, db)
    markup = _activation_language_markup(token) if record else None

    if not record or markup is None:
        _SESSIONS.pop(chat_id, None)
        await _send_message(chat_id, _ACTIVATION_INVALID_LINK_TEXT)
        return

    _SESSIONS[chat_id] = {"state": _ACTIVATION_LANGUAGE_SELECT_STATE, "activation_token": token}
    await _send_message(
        chat_id, activation_i18n.text("LANGUAGE_PROMPT", activation_i18n.DEFAULT_LANGUAGE), reply_markup=markup
    )


async def _handle_activation_language_callback(callback_query: dict, db: Session) -> None:
    """Handle a language-selector button press (H1F).

    Mirrors _handle_activation_callback's validation shape: never crashes
    on a malformed update, always answers the callback query at most once
    (only if Telegram supplied a callback_query_id), and validates the
    inbound callback_data through the same shared-shape builder
    (_build_activation_lang_payload) used to generate it BEFORE any DB
    lookup. Re-validates the token/record from scratch — never trusts that
    the language-select session is still valid.

    On success, stores the chosen language on a fresh
    "awaiting_activation_confirmation" session (the same state Phase A2
    used to enter directly) and sends the localized entry message with the
    localized "Activate Now" button — from here on, _handle_activation_callback
    (Phase A3) and everything after it reads session["language"] to stay in
    the chosen language for the rest of the flow.
    """
    if not isinstance(callback_query, dict):
        return

    callback_query_id = callback_query.get("id")
    data = callback_query.get("data")
    if not isinstance(data, str):
        data = ""

    if not data.startswith(_ACTIVATION_LANG_PAYLOAD_PREFIX):
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    remainder = data[len(_ACTIVATION_LANG_PAYLOAD_PREFIX):]
    lang_code, sep, token = remainder.partition("_")

    # Validate the payload format/length/charset/lang BEFORE the DB
    # lookup — mirrors every other activation callback handler's guard
    # order. None of the 4 supported language codes contain "_", so
    # partitioning on the first "_" unambiguously separates lang_code from
    # token even though tokens themselves may contain underscores.
    if not sep or _build_activation_lang_payload(lang_code, token) != data:
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
    if chat_id is None:
        return

    markup = _activation_entry_markup(token, lang_code)
    if markup is None:
        _SESSIONS.pop(chat_id, None)
        await _send_message(chat_id, _ACTIVATION_INVALID_LINK_TEXT)
        return

    _SESSIONS[chat_id] = {
        "state": "awaiting_activation_confirmation",
        "activation_token": token,
        "language": lang_code,
    }
    await _send_message(chat_id, activation_i18n.text("ENTRY", lang_code), reply_markup=markup)


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
      - ("reused", client): exactly one existing active match — same
        identity, same access code, same client_name. Hotfix H1B: the
        stored telegram_username is refreshed to whatever Telegram just
        sent (including None, if the customer removed their username) —
        this is metadata refresh only, never identity resolution.
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
        if existing.telegram_username != telegram_username:
            existing.telegram_username = telegram_username
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
    placeholder.

    Phase A4M: for a media slug only, likewise follows the access-code
    message with the media-input prompt and moves the session into
    _ACTIVATION_MEDIA_INPUT_STATE. Any other content_type (legacy/unset)
    still lands in the generic _ACTIVATION_SETUP_STATE with no follow-up
    message.
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
    # H1F: carry forward the language chosen at the selector step (stored on
    # the "awaiting_activation_confirmation" session _handle_activation_language_callback
    # just set) — falls back to English if missing/unrecognised.
    lang = _session_language(chat_id, token) if chat_id is not None else activation_i18n.DEFAULT_LANGUAGE

    from_user = callback_query.get("from")
    telegram_user_id = from_user.get("id") if isinstance(from_user, dict) else None
    if (
        not isinstance(telegram_user_id, int)
        or isinstance(telegram_user_id, bool)
        or telegram_user_id <= 0
    ):
        if chat_id is not None:
            await _send_message(chat_id, activation_i18n.text("MISSING_IDENTITY", lang))
        return

    # Re-fetch the slug's content_type fresh — _lookup_unactivated_record
    # already proved the RedirectLink exists and isn't archived above.
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == record.slug).first()
    if not link:
        if chat_id is not None:
            await _send_message(chat_id, activation_i18n.text("MISSING_IDENTITY", lang))
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
            await _send_message(chat_id, activation_i18n.text("CLIENT_BLOCKED", lang))
        return

    if status in ("inactive", "ambiguous"):
        db.rollback()
        if chat_id is not None:
            _SESSIONS.pop(chat_id, None)
            await _send_message(chat_id, activation_i18n.text("CLIENT_BLOCKED", lang))
        return

    # "created" always has a new row pending. "reused" only has something
    # pending when H1B's username refresh actually changed a scalar on the
    # client — an unchanged reused client must not trigger a commit.
    needs_commit = status == "created" or (
        status == "reused" and db.is_modified(client, include_collections=False)
    )
    if needs_commit:
        try:
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to commit BotClient resolution for activation token")
            if chat_id is not None:
                _SESSIONS.pop(chat_id, None)
                await _send_message(chat_id, activation_i18n.text("CLIENT_BLOCKED", lang))
            return

    if chat_id is not None:
        if link.content_type == "url":
            _SESSIONS[chat_id] = {
                "state": _ACTIVATION_URL_INPUT_STATE,
                "activation_token": token,
                "bot_client_id": client.id,
                "content_type": link.content_type,
                "language": lang,
            }
            await _send_message(chat_id, activation_i18n.text("ACCESS_CODE_READY", lang, code=client.access_code))
            await _send_message(chat_id, activation_i18n.text("URL_PROMPT", lang))
        elif link.content_type == "media":
            _SESSIONS[chat_id] = {
                "state": _ACTIVATION_MEDIA_INPUT_STATE,
                "activation_token": token,
                "bot_client_id": client.id,
                "content_type": link.content_type,
                "language": lang,
            }
            await _send_message(chat_id, activation_i18n.text("ACCESS_CODE_READY", lang, code=client.access_code))
            await _send_message(chat_id, activation_i18n.text("MEDIA_PROMPT", lang))
        else:
            _SESSIONS[chat_id] = {
                "state": _ACTIVATION_SETUP_STATE,
                "activation_token": token,
                "bot_client_id": client.id,
                "content_type": link.content_type,
                "language": lang,
            }
            await _send_message(chat_id, activation_i18n.text("ACCESS_CODE_READY", lang, code=client.access_code))


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
            await _answer_callback_query(
                callback_query_id, text=activation_i18n.text("CALLBACK_INVALID", _session_language(chat_id, token))
            )
        # Session-race guard: a losing/duplicate tap can reach here after a
        # Phase A5 finalize for this exact token already succeeded —
        # sequentially (the common case: the first tap already activated
        # and reset the session before this second tap's callback runs) or
        # concurrently. Either way, _SESSIONS[chat_id] may already be that
        # winner's authenticated state and must never be cleared just
        # because this token is no longer "unactivated".
        _pop_session_unless_already_activated(chat_id, session, token, db)
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
            await _answer_callback_query(
                callback_query_id, text=activation_i18n.text("CALLBACK_INVALID", _session_language(chat_id, token))
            )
        _pop_stale_session(chat_id, session)
        return

    if callback_query_id:
        await _answer_callback_query(callback_query_id)

    lang = session.get("language", activation_i18n.DEFAULT_LANGUAGE)

    if action == "confirm":
        session["confirmed_destination_url"] = session.get("pending_url")
        session.pop("pending_url", None)
        session["state"] = _ACTIVATION_SETUP_STATE
        _SESSIONS[chat_id] = session
        await _send_message(
            chat_id, activation_i18n.text("URL_SAVED", lang, url=session["confirmed_destination_url"])
        )
        return

    # action == "change"
    session.pop("pending_url", None)
    session.pop("confirmed_destination_url", None)
    session["state"] = _ACTIVATION_URL_INPUT_STATE
    _SESSIONS[chat_id] = session
    await _send_message(chat_id, activation_i18n.text("URL_RETRY", lang))


def _is_valid_pending_activation_media(pending) -> bool:
    """True if pending is a complete, well-formed pending_activation_media
    dict — validates every field of the schema (telegram_file_id,
    media_type, mime_type, original_filename, file_size), not just the two
    fields Phase A5 cannot proceed without, so a forged or corrupted
    session can never reach confirmed_activation_media with incomplete or
    inconsistent metadata. Extra keys are tolerated — only the required
    fields are checked.
    """
    if not isinstance(pending, dict):
        return False

    file_id = pending.get("telegram_file_id")
    if not isinstance(file_id, str) or not file_id.strip():
        return False

    media_type = pending.get("media_type")
    if not isinstance(media_type, str) or not media_type.strip():
        return False
    if media_type not in ALLOWED_MEDIA_TYPES:
        return False

    mime_type = pending.get("mime_type")
    if not isinstance(mime_type, str) or not mime_type.strip():
        return False
    # Reuses the same reverse-lookup the media-input branch used to
    # resolve media_type in the first place — catches a forged/corrupted
    # session pairing a mime_type with the wrong media_type, without
    # duplicating the ALLOWED_MEDIA_TYPES allowlist logic.
    if _media_type_for_mime(mime_type) != media_type:
        return False

    original_filename = pending.get("original_filename")
    if not isinstance(original_filename, str) or not original_filename.strip():
        return False

    file_size = pending.get("file_size")
    if file_size is not None:
        if isinstance(file_size, bool) or not isinstance(file_size, int):
            return False
        if file_size <= 0 or file_size > _MAX_TELEGRAM_MEDIA_BYTES:
            return False

    return True


async def _handle_a4m_confirmation_callback(callback_query: dict, db: Session) -> None:
    """Handle the Phase A4M "Confirm" / "Change Media" inline-button press.

    Mirrors _handle_a4u_confirmation_callback's structure and safety
    contract exactly, substituting the media-specific prefixes, DB-truth
    guard (_lookup_unactivated_media_link), and session keys
    (pending_activation_media / confirmed_activation_media in place of
    pending_url / confirmed_destination_url). See that function's docstring
    for the full duplicate-safety and fail-closed rationale — not repeated
    here.

    A4M performs zero persistent media storage: pending_activation_media
    holds only Telegram message metadata (file_id/media_type/mime_type/
    filename/file_size), never downloaded bytes or an R2/MediaAsset
    reference. Confirm therefore performs no DB or R2 writes — it only
    moves that dict, in-memory, to confirmed_activation_media for Phase A5
    to act on later.

    Confirm additionally fails closed (clears the session, generic invalid-
    link reply) if pending_activation_media is missing or incomplete
    (_is_valid_pending_activation_media) in an otherwise valid session — a
    confirm must never fabricate media data.

    Change Media has nothing to clean up in R2 or the DB — nothing was
    ever written there — so it only discards the in-memory pending/
    confirmed dicts before returning to _ACTIVATION_MEDIA_INPUT_STATE.
    """
    if not isinstance(callback_query, dict):
        return

    callback_query_id = callback_query.get("id")
    data = callback_query.get("data")
    if not isinstance(data, str):
        data = ""

    if data.startswith(_A4M_CONFIRM_PAYLOAD_PREFIX):
        prefix, action = _A4M_CONFIRM_PAYLOAD_PREFIX, "confirm"
    elif data.startswith(_A4M_CHANGE_PAYLOAD_PREFIX):
        prefix, action = _A4M_CHANGE_PAYLOAD_PREFIX, "change"
    else:
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    token = data[len(prefix):]

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
    # below and the ordinary confirm/change path.
    link = _lookup_unactivated_media_link(token, db)
    if link is None:
        if callback_query_id:
            await _answer_callback_query(
                callback_query_id, text=activation_i18n.text("CALLBACK_INVALID", _session_language(chat_id, token))
            )
        # Session-race guard: see the matching comment in
        # _handle_a4u_confirmation_callback — a Phase A5 finalize for this
        # exact token may have already succeeded (sequentially or
        # concurrently), so never clear the session just because this
        # token is no longer "unactivated".
        _pop_session_unless_already_activated(chat_id, session, token, db)
        return

    # Duplicate-safety: a repeat Confirm tap after the session already
    # advanced past confirmation (same token) is a no-op.
    if (
        action == "confirm"
        and session_matches_token
        and session.get("state") == _ACTIVATION_SETUP_STATE
        and "confirmed_activation_media" in session
    ):
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    # Duplicate-safety: a repeat Change Media tap after the session already
    # returned to media input (same token) is likewise a no-op.
    if (
        action == "change"
        and session_matches_token
        and session.get("state") == _ACTIVATION_MEDIA_INPUT_STATE
    ):
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    valid_session = session_matches_token and session.get("state") == _ACTIVATION_MEDIA_CONFIRM_STATE
    if not valid_session:
        if callback_query_id:
            await _answer_callback_query(
                callback_query_id, text=activation_i18n.text("CALLBACK_INVALID", _session_language(chat_id, token))
            )
        _pop_stale_session(chat_id, session)
        return

    if action == "confirm" and not _is_valid_pending_activation_media(session.get("pending_activation_media")):
        # A valid, in-confirmation session with no (or incomplete) pending
        # media metadata can't legitimately happen through the normal flow
        # — fail closed rather than confirm nothing.
        if callback_query_id:
            await _answer_callback_query(
                callback_query_id, text=activation_i18n.text("CALLBACK_INVALID", _session_language(chat_id, token))
            )
        _pop_stale_session(chat_id, session)
        return

    if callback_query_id:
        await _answer_callback_query(callback_query_id)

    lang = session.get("language", activation_i18n.DEFAULT_LANGUAGE)

    if action == "confirm":
        # In-memory move only — no DB or R2 write. Phase A5 performs the
        # actual download/upload/MediaAsset creation from this dict.
        session["confirmed_activation_media"] = session.get("pending_activation_media")
        session.pop("pending_activation_media", None)
        session["state"] = _ACTIVATION_SETUP_STATE
        _SESSIONS[chat_id] = session
        await _send_message(chat_id, activation_i18n.text("MEDIA_SAVED", lang))
        return

    # action == "change" — nothing was ever persisted, so there is nothing
    # to clean up in R2 or the DB; just discard the in-memory dicts.
    session.pop("pending_activation_media", None)
    session.pop("confirmed_activation_media", None)
    session["state"] = _ACTIVATION_MEDIA_INPUT_STATE
    _SESSIONS[chat_id] = session
    await _send_message(chat_id, activation_i18n.text("MEDIA_RETRY", lang))


# ---------------------------------------------------------------------------
# Activation Engine v1 — Phase A5 (Activation Finalization)
#
# Runs INLINE, in the same request, immediately after A4U/A4M's own Confirm
# step lands the session in _ACTIVATION_SETUP_STATE with confirmed content —
# no second button, no extra tap. A4U/A4M's Confirm handlers themselves are
# untouched: they still only stash validated content into the session. The
# two call sites that invoke _finalize_activation_confirmation are the
# webhook route (right after dispatching an a4uconfirm_/a4uchange_ or
# a4mconfirm_/a4mchange_ callback) and _handle_message's A4U typed-YES
# compatibility branch — the only other place a Confirm can happen. Both
# call sites call it unconditionally; the function itself no-ops unless
# there's actually something to finalize.
#
# A retap of Confirm (already a no-op inside A4U/A4M's own duplicate-safety
# branch) or any further message while still sitting in
# _ACTIVATION_SETUP_STATE (see the replaced placeholder in _handle_message
# below) both re-enter this same function — that doubles as the retry path
# after a failed attempt, without a dedicated button.
# ---------------------------------------------------------------------------

_ACTIVATION_ALREADY_COMPLETE_TEXT = "This product has already been activated."
_ACTIVATION_FINALIZE_FAILED_TEXT = (
    "Something went wrong completing activation. Please try again in a moment."
)
_ACTIVATION_ASSIGNMENT_CONFLICT_TEXT = (
    "This product can't be activated right now. Please contact SHADZ support."
)
# Sent by the narrow retry surface in _handle_message when a session is
# still stuck in _ACTIVATION_SETUP_STATE (an earlier finalize attempt
# failed) and the incoming message wasn't the specific retry trigger for
# its content type — reuses A4U's own existing "Confirm"/typed-YES UX
# rather than treating arbitrary text as an implicit retry.
_ACTIVATION_FINALIZE_RETRY_URL_TEXT = (
    "Please tap Confirm above, or reply YES, to finish activating your product."
)
_ACTIVATION_FINALIZE_RETRY_MEDIA_TEXT = (
    "Please tap Confirm above to finish activating your product."
)
# "{code}" is the same plain-text BotClient.access_code already sent by
# _ACCESS_CODE_READY_TEXT earlier in this flow — not a new secret.
_ACTIVATION_COMPLETE_TEXT = (
    "Activation completed. Your SHADZ product is now active.\n\n"
    "Access code: {code}\n\n"
    "Use your code any time to manage this product."
)


def _callback_chat_id(callback_query: dict) -> int | None:
    """Extract chat_id from a callback_query, or None for a malformed one.

    A small new helper for Phase A5's own call sites only — the existing
    A2/A3/A4U/A4M handlers each already inline this same extraction and are
    left as-is (not refactored to use this).
    """
    if not isinstance(callback_query, dict):
        return None
    message = callback_query.get("message")
    chat = message.get("chat") if isinstance(message, dict) else None
    return chat.get("id") if isinstance(chat, dict) else None


async def _reject_finalization(
    chat_id: int, session: dict | None, text: str | None = None
) -> None:
    """Shared fail-closed exit for _finalize_activation_confirmation.

    Sends an optional message and clears the activation session via
    _pop_stale_session — see that helper for why the identity check matters
    for the idempotent "someone else already finalized this" case. Never
    touches the DB — callers only reach this after any staged DB changes
    have already been rolled back (or were never staged).
    """
    if text is not None:
        await _send_message(chat_id, text)
    _pop_stale_session(chat_id, session)


async def _finalize_activation_confirmation(chat_id: int, db: Session) -> None:
    """Immediately finalize an A4U/A4M activation once its Confirm step has
    landed the session in _ACTIVATION_SETUP_STATE with confirmed content.

    A no-op unless the session is actually sitting in that state with
    confirmed_destination_url or confirmed_activation_media set — safe to
    call unconditionally after every A4U/A4M Confirm/Change dispatch (a
    Change never reaches that state) and after any later message/callback
    that lands here again (the retry path after a failed attempt).

    Re-fetches every authoritative record fresh — never trusts the session
    for anything beyond the token/content_type/bot_client_id it already
    carries, and reuses _lookup_unactivated_record for the exists/
    unactivated/link-not-archived checks it already performs for A2/A3.

    Ownership: a BotClientSlug for (client, slug) is created if missing, or
    reused as-is if it already points at this exact client. If it points at
    a DIFFERENT client, this fails closed with zero mutation. The DB's own
    UNIQUE constraint on BotClientSlug.slug is the defense-in-depth backstop
    against a genuine race with an out-of-band admin assignment (caught by
    the outer except below).

    Concurrency: the transition of ActivationRecord.activation_status from
    "unactivated" to "activated" is performed as a single conditional
    UPDATE ... WHERE activation_status = 'unactivated', and the returned
    row count is checked. SQLite serializes concurrent writers, so two
    simultaneous finalizations for the same token can never both see
    rowcount == 1 — the loser's entire transaction (including any
    BotClientSlug/MediaAsset/SlugMedia it staged) is rolled back untouched,
    and it exits through the same silent, no-mutation path as an
    already-activated token found on the early read below (that early read
    is a cheap fast-path for the common case; the UPDATE's row count is
    what actually guarantees correctness under a genuine race).
    """
    session = _SESSIONS.get(chat_id)
    if session is None or session.get("state") != _ACTIVATION_SETUP_STATE:
        return
    if "confirmed_destination_url" not in session and "confirmed_activation_media" not in session:
        return

    lang = session.get("language", activation_i18n.DEFAULT_LANGUAGE)
    token = session.get("activation_token")
    content_type = "url" if "confirmed_destination_url" in session else "media"

    record = _lookup_unactivated_record(token, db)
    if record is None:
        # Either genuinely invalid/archived/missing, or a concurrent
        # winner already activated it — check raw DB truth to tell the
        # two apart, independent of anything cached in the session. An
        # already-"activated" record is a safe, silent no-op: never
        # reveals which case occurred.
        raw_status = (
            db.query(models.ActivationRecord.activation_status)
            .filter(models.ActivationRecord.activation_token == token)
            .scalar()
            if token else None
        )
        if raw_status == "activated":
            await _reject_finalization(chat_id, session, None)
        else:
            await _reject_finalization(chat_id, session, activation_i18n.text("INVALID_LINK", lang))
        return

    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == record.slug).first()
    if not link or link.content_type != content_type:
        await _reject_finalization(chat_id, session, activation_i18n.text("INVALID_LINK", lang))
        return

    bot_client_id = session.get("bot_client_id")
    client = None
    if isinstance(bot_client_id, int) and not isinstance(bot_client_id, bool):
        client = (
            db.query(models.BotClient)
            .filter(models.BotClient.id == bot_client_id, models.BotClient.is_active.is_(True))
            .first()
        )
    if client is None:
        await _reject_finalization(chat_id, session, activation_i18n.text("CLIENT_BLOCKED", lang))
        return

    confirmed_url = None
    pending_media = None
    if content_type == "url":
        confirmed_url = session.get("confirmed_destination_url")
        if (
            not isinstance(confirmed_url, str)
            or not (confirmed_url.startswith("http://") or confirmed_url.startswith("https://"))
            or _is_blocked_destination_url(confirmed_url)
        ):
            await _reject_finalization(chat_id, session, activation_i18n.text("INVALID_LINK", lang))
            return
    else:
        pending_media = session.get("confirmed_activation_media")
        if not _is_valid_pending_activation_media(pending_media):
            await _reject_finalization(chat_id, session, activation_i18n.text("INVALID_LINK", lang))
            return

    # Ownership: reuse an existing assignment to this exact client, fail
    # closed on one that belongs to someone else, otherwise stage a new one.
    existing_assignment = (
        db.query(models.BotClientSlug).filter(models.BotClientSlug.slug == record.slug).first()
    )
    if existing_assignment is not None and existing_assignment.bot_client_id != client.id:
        await _reject_finalization(chat_id, session, activation_i18n.text("ASSIGNMENT_CONFLICT", lang))
        return
    assignment_needed = existing_assignment is None

    # Media: download from Telegram and upload to R2 BEFORE any DB write —
    # mirrors the existing T1C replacement-media flow. A failure here
    # touches no DB row and leaves the session/token untouched, so
    # re-tapping Confirm retries this same function from scratch.
    #
    # Concurrency note: this upload can't be part of the SQLite
    # transaction below, so two genuinely concurrent finalizations for the
    # same token can both reach here and both upload before the atomic
    # compare-and-set (below) picks a winner. The loser's uploaded object
    # is never referenced by any DB row and is never cleaned up — a
    # documented, accepted orphan-R2 risk (same class as an ordinary
    # post-upload commit failure, and the same one T1C's own replacement-
    # media flow already carries), not something this phase adds cleanup
    # for.
    media_asset_kwargs = None
    if content_type == "media":
        try:
            file_bytes = await _download_telegram_file(pending_media["telegram_file_id"])
        except Exception:
            logger.exception(
                "A5 media download failed for chat_id=%s slug=%s", chat_id, record.slug
            )
            await _send_message(chat_id, activation_i18n.text("FINALIZE_FAILED", lang))
            return

        if len(file_bytes) > _MAX_TELEGRAM_MEDIA_BYTES:
            await _send_message(chat_id, activation_i18n.text("FINALIZE_FAILED", lang))
            return

        storage_key = _make_storage_key(pending_media["media_type"], pending_media["original_filename"])
        public_url = _make_public_url(storage_key)
        try:
            _upload_bytes_to_r2(storage_key, file_bytes, pending_media["mime_type"])
        except Exception:
            logger.exception(
                "A5 R2 upload failed for chat_id=%s slug=%s", chat_id, record.slug
            )
            await _send_message(chat_id, activation_i18n.text("FINALIZE_FAILED", lang))
            return

        media_asset_kwargs = {
            "media_type": pending_media["media_type"],
            "storage_provider": "r2",
            "storage_key": storage_key,
            "public_url": public_url,
            "original_filename": pending_media["original_filename"],
            "mime_type": pending_media["mime_type"],
            "file_size": len(file_bytes),
        }

    # Everything from here on is staged together and either committed as
    # one unit or rolled back as one unit: the BotClientSlug assignment,
    # content persistence, and the activation-record transition.
    try:
        if assignment_needed:
            db.add(models.BotClientSlug(bot_client_id=client.id, slug=record.slug))

        if content_type == "url":
            link.destination_url = confirmed_url
        else:
            asset = models.MediaAsset(**media_asset_kwargs)
            db.add(asset)
            db.flush()
            (
                db.query(models.SlugMedia)
                .filter(models.SlugMedia.slug == record.slug, models.SlugMedia.is_active == True)
                .update({"is_active": False})
            )
            db.add(models.SlugMedia(slug=record.slug, media_asset_id=asset.id, is_active=True))

        # Atomic compare-and-set: only a caller that still finds the row
        # "unactivated" at the moment this statement executes can flip it.
        claimed = (
            db.query(models.ActivationRecord)
            .filter(
                models.ActivationRecord.activation_token == token,
                models.ActivationRecord.activation_status == "unactivated",
            )
            .update(
                {
                    "activation_status": "activated",
                    "owner_client_id": client.id,
                    "activated_at": datetime.now(timezone.utc),
                },
                synchronize_session=False,
            )
        )
        if claimed != 1:
            # Lost the race to a concurrent finalize (or the token went
            # stale between the read above and here) — roll back
            # everything staged in this transaction, including the
            # BotClientSlug/content changes, and exit through the same
            # silent no-mutation path as the early idempotency check.
            db.rollback()
            await _reject_finalization(chat_id, session, None)
            return

        db.commit()
    except Exception:
        db.rollback()
        logger.exception(
            "A5 finalization commit failed for chat_id=%s slug=%s", chat_id, record.slug
        )
        await _send_message(chat_id, activation_i18n.text("FINALIZE_FAILED", lang))
        return

    # Success — clear ALL activation/authenticated-management session state
    # and return the chat to the normal access-code entry point. Activation
    # never keeps the customer automatically logged in: they must still
    # enter their access code afterward to manage anything, exactly like
    # any other visit — the completion message may quote that code, but it
    # does not substitute for entering it. The final welcome-back prompt
    # reverts to English — the chosen language belonged to the activation
    # session only, which just ended; ordinary access-code login (T1B) is
    # out of H1F's locked scope.
    _SESSIONS[chat_id] = {"state": "awaiting_code"}
    await _send_message(chat_id, activation_i18n.text("COMPLETE", lang, code=client.access_code))
    await _send_message(chat_id, "Welcome to SHADZ. Please enter your access code.")


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


def _reconcile_assigned_slug_activation(client: "models.BotClient", db: Session) -> None:
    """Idempotently reconcile this BotClient's assigned, non-archived
    url/media slugs to Activated (UI3D-C1).

    Called after every successful access-code authentication — not just the
    client's first login — so it stays safely retryable: a slug assigned
    after the client's first Telegram login, a slug that failed to
    reconcile previously, or a slug that was archived and has since been
    restored can all be picked up by a later login. Already-consistent
    (activated, owned by this client) slugs are a no-op.

    Reuses _get_active_assigned_slugs (already excludes archived and only
    ever contains url/media, per assign_slug's own content-type gate).

    Best-effort, per-slug: each slug is committed (or rolled back) on its
    own. A failure or ownership conflict on one slug is logged and skipped
    — it never rolls back another slug's already-committed reconciliation,
    never undoes the caller's already-committed login, and never raises out
    of this function (the caller must be able to proceed to the normal Bot
    menu regardless of reconciliation outcome).

    Never touches: activation_token on an existing record, destination_url,
    SlugMedia/active media, or the BotClientSlug assignment row itself.
    """
    if not client.telegram_user_id:
        return

    for item in _get_active_assigned_slugs(client.id, db):
        slug = item["slug"]
        if item["content_type"] not in ("url", "media"):
            continue  # defensive — assign_slug already guarantees this

        try:
            record = (
                db.query(models.ActivationRecord)
                .filter(models.ActivationRecord.slug == slug)
                .first()
            )

            if record is None:
                # Legacy slug with no ActivationRecord yet — create it and,
                # within this same uncommitted transaction, immediately
                # overwrite it to activated before the first commit. The
                # public Activation Gateway (link_public.resolve_activation_
                # redirect) only ever gates on a *committed* row with
                # activation_status == "unactivated", so this legacy record
                # is never externally observable in an unactivated state.
                token = _generate_activation_token(db)
                record = models.create_activation_record_for_slug(db, slug, token)
                record.activation_status = "activated"
                record.owner_client_id = client.id
                record.activated_at = datetime.now(timezone.utc)
                db.commit()
                continue

            if record.activation_status == "activated":
                if record.owner_client_id == client.id:
                    continue  # already consistent — no-op
                logger.warning(
                    "UI3D-C1 reconciliation conflict: slug=%s assigned to "
                    "bot_client_id=%s but ActivationRecord.owner_client_id=%s "
                    "(already activated) — leaving untouched",
                    slug, client.id, record.owner_client_id,
                )
                continue

            # unactivated
            if record.owner_client_id is not None and record.owner_client_id != client.id:
                logger.warning(
                    "UI3D-C1 reconciliation conflict: slug=%s assigned to "
                    "bot_client_id=%s but ActivationRecord.owner_client_id=%s "
                    "(unactivated) — leaving untouched",
                    slug, client.id, record.owner_client_id,
                )
                continue

            record.activation_status = "activated"
            record.owner_client_id = client.id
            record.activated_at = datetime.now(timezone.utc)
            db.commit()
        except Exception:
            db.rollback()
            logger.exception(
                "UI3D-C1 reconciliation failed for slug=%s bot_client_id=%s — "
                "skipping; safe to retry on a later successful access-code login",
                slug, client.id,
            )


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


async def _enter_slug_list_state(chat_id: int, bot_client_id: int, slugs: list[dict]) -> None:
    """Enter awaiting_slug_selection and immediately show the numbered
    list — the only place this state is ever entered, so it can never be
    reached silently without the list being displayed. Shared by the
    login flow (multiple assigned slugs) and _return_to_slug_list_or_login
    below, so the two paths cannot diverge.
    """
    _SESSIONS[chat_id] = {
        "state": "awaiting_slug_selection",
        "bot_client_id": bot_client_id,
        "slugs": slugs,
    }
    await _send_message(chat_id, _format_slug_menu(slugs))


async def _return_to_slug_list_or_login(chat_id: int, session: dict) -> None:
    """Return from a per-slug management flow (cancel, or after a slug
    turns out to no longer be available) to the correct resting state.

    Never leaves a client sitting in a hidden, undisplayed
    awaiting_slug_selection state, and never leaves a single-slug client
    in that state at all: with zero or one active assigned slugs there is
    nothing meaningful left to "select", so this goes straight back to the
    plain access-code entry point instead (matching a fresh visit — the
    client must re-enter their code to resume managing anything, exactly
    like the rest of this bot's login-gated design). With more than one,
    it returns to awaiting_slug_selection and immediately re-renders the
    numbered list via _enter_slug_list_state, the same helper the login
    flow uses, so the two paths can never diverge.
    """
    slugs = session.get("slugs", [])
    if len(slugs) <= 1:
        _SESSIONS[chat_id] = {"state": "awaiting_code"}
        await _send_message(chat_id, "Welcome to SHADZ. Please enter your access code.")
        return
    await _enter_slug_list_state(chat_id, session["bot_client_id"], slugs)


# ---------------------------------------------------------------------------
# Telegram URL Auto Normalization (Hotfix H1D) — applies to Telegram bot
# destination-URL input only (the T1B self-service "awaiting_new_url" flow
# and the Activation Engine A4U flow). Trims whitespace and, when the
# customer's input has no http(s) scheme, prepends "https://" so plain
# domains like "google.com" work without typing a scheme. An explicitly
# supplied http:// or https:// (any case) is preserved verbatim — never
# rewritten or double-prefixed. Scheme detection is done on the raw trimmed
# input via regex, not urlparse(...).scheme — urlparse treats anything
# before a ":" as a scheme (including a bare "example.com" in
# "example.com:8080/path"), which would wrongly reject a scheme-less
# host:port input. Any other explicit scheme (javascript:, file:, ftp:,
# ...) is rejected outright. Scheme-less input is only normalized when its
# parsed hostname contains a dot (i.e. looks like a domain), so unscoped
# junk text like "not-a-url" still fails validation instead of silently
# becoming a URL. Does not replace _is_blocked_destination_url — callers
# still run the normalized result through that existing guard.
# ---------------------------------------------------------------------------

_EXPLICIT_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+\-]*):")


def _normalize_telegram_destination_url(text: str) -> str | None:
    """Return a normalized http(s) URL for Telegram destination-URL input,
    or None if the input can't be turned into a valid http(s) URL."""
    trimmed = (text or "").strip()
    if not trimmed:
        return None

    if re.match(r"^https?://", trimmed, re.IGNORECASE):
        candidate = trimmed
        added_scheme = False
    else:
        if _EXPLICIT_SCHEME_RE.match(trimmed):
            # An explicit non-http(s) scheme (javascript:, file:, ftp:,
            # ...) — never prepend on top of it.
            return None
        candidate = "https://" + trimmed
        added_scheme = True

    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None

    if parsed.scheme.lower() not in ("http", "https"):
        return None
    hostname = parsed.hostname
    if not hostname:
        return None
    if added_scheme and "." not in hostname:
        return None
    try:
        parsed.port
    except ValueError:
        return None

    return candidate


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


async def _enter_slug_management_state(
    chat_id: int, bot_client_id: int, slugs: list[dict], chosen_slug: str, db: Session
) -> None:
    """Enter the correct per-content-type management state for a chosen
    slug, branching on the authoritative DB content_type.

    Shared by two call sites so both apply identical authorization/state-
    entry logic: the single-slug auto-select path (login with exactly one
    active assigned slug — no numbered list is ever shown) and the
    numbered-selection path (awaiting_slug_selection, once the customer has
    picked one of several). `slugs` — the full assigned-slug list, however
    many items it has — is carried into the resulting session dict so
    _return_to_slug_list_or_login keeps working for a later /cancel or
    completion regardless of which path got here.
    """
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == chosen_slug).first()
    if not link or link.is_archived is True:
        await _send_message(chat_id, "That slug is no longer available.")
        await _return_to_slug_list_or_login(
            chat_id, {"bot_client_id": bot_client_id, "slugs": slugs}
        )
        return

    if link.content_type == "media":
        status = _current_media_status_text(chosen_slug, db)
        _SESSIONS[chat_id] = {
            "state": "awaiting_media_upload",
            "bot_client_id": bot_client_id,
            "slugs": slugs,
            "selected_slug": chosen_slug,
        }
        await _send_message(
            chat_id,
            f"Current media: {status}\n\n"
            "Send a replacement file (photo, document, video, or GIF) to update "
            "this slug's media, or /cancel.",
        )
        return

    # url — the only other content_type a BotClientSlug can ever be
    # assigned for (page slugs are rejected at admin-assignment time,
    # matching the existing fail-closed behaviour there, so there is
    # nothing further to branch on here).
    _SESSIONS[chat_id] = {
        "state": "awaiting_new_url",
        "bot_client_id": bot_client_id,
        "slugs": slugs,
        "selected_slug": chosen_slug,
    }
    await _send_message(
        chat_id,
        f"Current destination for '{chosen_slug}':\n{link.destination_url}\n\n"
        "Reply with the new destination URL — a domain such as example.com "
        "or a full http:// / https:// URL — or /cancel.",
    )


# ---------------------------------------------------------------------------
# T1B URL Management — Confirm/Change/Cancel
#
# Mirrors the Activation Engine's own Confirm/Change button pattern (A4U)
# for the pre-existing self-service URL-update flow (awaiting_confirmation
# state) — with one shared action implementation for BOTH the inline
# buttons and the typed YES/NO/CHANGE compatibility fallback in
# _handle_message, so the two entry points can never diverge. Unlike A4U's
# activation tokens, nothing here needs to survive across chats/devices or
# a webhook redelivery window spanning multiple distinct records — the
# whole flow lives inside one already-authenticated chat's own _SESSIONS
# entry — so the callback_data itself carries no per-request data at all:
# three fixed, validated, action-only strings. Every real value (which
# slug, the new destination) comes only from _SESSIONS[chat_id]
# (re-validated) and a fresh DB lookup, never from the callback payload.
#
# Idempotency: the pending-confirmation context is claimed by
# _claim_url_management_context, which mutates _SESSIONS[chat_id]
# synchronously with no `await` in between the validity check and the
# claim — asyncio only switches tasks at an `await`, so nothing else can
# observe or act on this session between those two lines. A second
# Confirm/Change/Cancel delivery — sequential duplicate, a typed message
# racing a button tap, or vice versa — always finds the claimed marker
# instead of "awaiting_confirmation" and fails closed, whichever one it
# is. This is deliberately just an in-memory session-dict claim, not
# activation-style DB-level CAS — there is no multi-writer database race
# here to guard against, only Python tasks sharing one process's
# _SESSIONS dict.
# ---------------------------------------------------------------------------

_URL_MANAGEMENT_CONFIRM_CALLBACK = "urlmgmt_confirm"
_URL_MANAGEMENT_CHANGE_CALLBACK = "urlmgmt_change"
_URL_MANAGEMENT_CANCEL_CALLBACK = "urlmgmt_cancel"
_URL_MANAGEMENT_CLAIMED_STATE = "awaiting_confirmation_claimed"
_URL_MANAGEMENT_UNAVAILABLE_TEXT = "This action is no longer available."
# H1G: distinguishes an identity-driven session reset from every other
# reason _claim_url_management_context can fail to claim (stale/foreign-
# chat/already-claimed), without a broader result-object refactor.
_URL_MANAGEMENT_IDENTITY_INVALIDATED = object()
_H1G_SESSION_INVALID_TEXT = (
    "This session is no longer valid for your Telegram account. "
    "Please enter your access code to continue."
)


def _url_management_confirmation_markup() -> dict:
    return {
        "inline_keyboard": [[
            {"text": "Confirm", "callback_data": _URL_MANAGEMENT_CONFIRM_CALLBACK},
            {"text": "Change", "callback_data": _URL_MANAGEMENT_CHANGE_CALLBACK},
            {"text": "Cancel", "callback_data": _URL_MANAGEMENT_CANCEL_CALLBACK},
        ]]
    }


def _claim_url_management_context(chat_id: int, from_user: dict, db: Session) -> dict | None:
    """Validate and claim the pending awaiting_confirmation context for
    chat_id.

    Shared by both the inline-button callback handler and the typed
    YES/NO/CHANGE fallback in _handle_message so the two entry points
    apply identical validity/claim rules and can never diverge. Returns
    the claimed values (bot_client_id, slugs, selected_slug,
    pending_value, and the exact claimed_session object for identity
    re-checks); or None if there is nothing valid to claim — a genuinely
    invalid/stale/foreign-chat session, one already claimed by a prior or
    racing delivery, or (pre-H1G behaviour, unchanged) its BotClient is
    inactive or missing; or _URL_MANAGEMENT_IDENTITY_INVALIDATED (H1G) if
    the session was otherwise valid and its BotClient IS active, but no
    longer owned by the current Telegram sender — distinguished from plain
    None specifically so callers can tell the customer to log in again,
    instead of the generic "no longer available" the inactive/missing
    case still gets.

    H1G: this is the only entry point through which an authenticated
    Confirm/Change/Cancel action can reach _apply_url_management_action —
    the typed fallback in _handle_message is already covered by its own
    earlier identity check, but the inline-button callback route
    (_handle_url_management_confirmation_callback) has no other
    revalidation point, so the check lives here to cover both without
    duplicating it.
    """
    session = _SESSIONS.get(chat_id) if chat_id is not None else None
    valid_session = (
        session is not None
        and session.get("state") == "awaiting_confirmation"
        and isinstance(session.get("selected_slug"), str)
        and isinstance(session.get("pending_value"), str)
    )
    if not valid_session:
        return None

    bot_client_id = session.get("bot_client_id")
    if _resolve_active_bot_client(bot_client_id, db) is None:
        # Inactive/missing BotClient — the pre-H1G callback behaviour:
        # block and reset the session, but this is NOT an H1G identity
        # invalidation, so it must never get the H1G "session is no longer
        # valid for your Telegram account" message — only plain None,
        # which callers already answer with the generic unavailable text.
        _SESSIONS[chat_id] = {"state": "awaiting_code"}
        return None

    if _resolve_authenticated_bot_client(bot_client_id, from_user, db) is None:
        _SESSIONS[chat_id] = {"state": "awaiting_code"}
        return _URL_MANAGEMENT_IDENTITY_INVALIDATED

    slugs = session.get("slugs", [])
    selected_slug = session["selected_slug"]
    pending_value = session["pending_value"]
    claimed_session = {
        "state": _URL_MANAGEMENT_CLAIMED_STATE,
        "bot_client_id": bot_client_id,
        "slugs": slugs,
        "selected_slug": selected_slug,
    }
    _SESSIONS[chat_id] = claimed_session
    return {
        "bot_client_id": bot_client_id,
        "slugs": slugs,
        "selected_slug": selected_slug,
        "pending_value": pending_value,
        "claimed_session": claimed_session,
    }


async def _apply_url_management_action(chat_id: int, action: str, claim: dict, db: Session) -> None:
    """Perform the actual Confirm/Change/Cancel action using an
    already-claimed context from _claim_url_management_context.

    This is the one piece of logic the inline-button callback handler and
    the typed YES/NO/CHANGE fallback both call, so persistence, rollback/
    retry, and the single/multi-slug return behaviour can never diverge
    between the two entry points. `action` is one of
    "confirm"/"change"/"cancel". On a DB failure during confirm, the
    transaction is rolled back and the session is restored to a fresh
    "awaiting_confirmation" with the same pending slug/URL, so the
    customer can safely retry without retyping.
    """
    bot_client_id = claim["bot_client_id"]
    slugs = claim["slugs"]
    selected_slug = claim["selected_slug"]
    pending_value = claim["pending_value"]

    if action == "change":
        _SESSIONS[chat_id] = {
            "state": "awaiting_new_url",
            "bot_client_id": bot_client_id,
            "slugs": slugs,
            "selected_slug": selected_slug,
        }
        await _send_message(
            chat_id,
            "No problem — please send the new destination URL (must start with "
            "http:// or https://), or /cancel.",
        )
        return

    if action == "cancel":
        await _send_message(chat_id, "Cancelled.")
        await _return_to_slug_list_or_login(
            chat_id, {"bot_client_id": bot_client_id, "slugs": slugs}
        )
        return

    # confirm — re-validate DB truth fresh, never trust the content_type
    # cached at slug-selection time.
    try:
        link = (
            db.query(models.RedirectLink)
            .filter(models.RedirectLink.slug == selected_slug)
            .first()
        )
        if not link or link.is_archived is True or link.content_type != "url":
            await _send_message(chat_id, "That slug is no longer available.")
            await _return_to_slug_list_or_login(
                chat_id, {"bot_client_id": bot_client_id, "slugs": slugs}
            )
            return
        link.destination_url = pending_value
        db.commit()
    except Exception:
        db.rollback()
        logger.exception(
            "URL management commit failed for chat_id=%s slug=%s", chat_id, selected_slug
        )
        _SESSIONS[chat_id] = {
            "state": "awaiting_confirmation",
            "bot_client_id": bot_client_id,
            "slugs": slugs,
            "selected_slug": selected_slug,
            "pending_value": pending_value,
        }
        await _send_message(chat_id, "Something went wrong saving the update. Please try again.")
        return

    await _send_message(chat_id, f"Done. '{selected_slug}' now points to {pending_value}.")
    await _return_to_slug_list_or_login(
        chat_id, {"bot_client_id": bot_client_id, "slugs": slugs}
    )


async def _handle_url_management_confirmation_callback(callback_query: dict, db: Session) -> None:
    """Handle the T1B URL-management Confirm/Change/Cancel inline-button
    press (awaiting_confirmation state).

    Never crashes on a malformed update. callback_data is one of three
    fixed literals with no dynamic component, so nothing from the payload
    is ever trusted for the slug, URL, or client identity.

    Claims the pending context via _claim_url_management_context before
    the only `await` in this function (_answer_callback_query), then
    re-checks _SESSIONS[chat_id] is still that exact claimed object
    immediately afterward, before calling _apply_url_management_action —
    never relies solely on the claim captured before that await.
    """
    if not isinstance(callback_query, dict):
        return

    callback_query_id = callback_query.get("id")
    data = callback_query.get("data")
    action_by_callback = {
        _URL_MANAGEMENT_CONFIRM_CALLBACK: "confirm",
        _URL_MANAGEMENT_CHANGE_CALLBACK: "change",
        _URL_MANAGEMENT_CANCEL_CALLBACK: "cancel",
    }
    action = action_by_callback.get(data) if isinstance(data, str) else None
    if action is None:
        if callback_query_id:
            await _answer_callback_query(callback_query_id)
        return

    chat_id = _callback_chat_id(callback_query)
    claim = (
        _claim_url_management_context(chat_id, callback_query.get("from"), db)
        if chat_id is not None else None
    )
    if claim is _URL_MANAGEMENT_IDENTITY_INVALIDATED:
        if callback_query_id:
            await _answer_callback_query(callback_query_id, text=_URL_MANAGEMENT_UNAVAILABLE_TEXT)
        await _send_message(chat_id, _H1G_SESSION_INVALID_TEXT)
        return
    if claim is None:
        if callback_query_id:
            await _answer_callback_query(callback_query_id, text=_URL_MANAGEMENT_UNAVAILABLE_TEXT)
        return

    if callback_query_id:
        await _answer_callback_query(callback_query_id)

    # Re-check identity immediately after the only await above — nothing
    # legitimate touches this exact object once claimed, but this is the
    # explicit "never rely solely on a pre-await claim" guard.
    if _SESSIONS.get(chat_id) is not claim["claimed_session"]:
        return

    await _apply_url_management_action(chat_id, action, claim, db)


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


def _telegram_sender_id(from_user: dict) -> str | None:
    """Extract the current message/callback's numeric Telegram sender id as
    a string, for comparison against BotClient.telegram_user_id (H1G). Same
    int/non-bool/positive validation as the activation entry's from.id
    check, and the same str() conversion access-code login already uses
    when binding a BotClient to its Telegram owner.
    """
    telegram_user_id = from_user.get("id") if isinstance(from_user, dict) else None
    if (
        not isinstance(telegram_user_id, int)
        or isinstance(telegram_user_id, bool)
        or telegram_user_id <= 0
    ):
        return None
    return str(telegram_user_id)


def _resolve_active_bot_client(
    bot_client_id: int | None, db: Session
) -> "models.BotClient | None":
    """The active-only half of _resolve_authenticated_bot_client, split out
    so a caller can distinguish the pre-existing "inactive/missing
    BotClient" case from an H1G identity mismatch — see
    _claim_url_management_context, which needs that distinction to avoid
    sending the H1G identity-mismatch message for a plain deactivation.
    Same query the pre-existing T1G deactivation check in _handle_message
    already used.
    """
    if bot_client_id is None:
        return None
    return (
        db.query(models.BotClient)
        .filter(models.BotClient.id == bot_client_id, models.BotClient.is_active.is_(True))
        .first()
    )


def _resolve_authenticated_bot_client(
    bot_client_id: int | None, from_user: dict, db: Session
) -> "models.BotClient | None":
    """H1G: the single shared authenticated-session identity check, used by
    every authenticated management entry point — both _handle_message and
    the url-management inline-button callback route through this.

    Resolves bot_client_id to an active BotClient (via
    _resolve_active_bot_client), then additionally requires its
    telegram_user_id to still match the current Telegram sender (numeric
    id only — never username). Returns None if bot_client_id is missing,
    the BotClient is inactive, or the identity no longer matches; callers
    own resetting/invalidating the session and picking the right response
    for their own entry point.
    """
    active_client = _resolve_active_bot_client(bot_client_id, db)
    if active_client is None:
        return None
    sender_telegram_id = _telegram_sender_id(from_user)
    if sender_telegram_id is None or active_client.telegram_user_id != sender_telegram_id:
        return None
    return active_client


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

            # H1G: an active BotClient row is not enough — for authenticated
            # slug-management sessions (reached only via access-code login
            # below; identified structurally by NOT carrying an
            # "activation_token", the key every Activation Engine session
            # always carries, so this can never miss a future authenticated
            # management state the way a hardcoded state whitelist could),
            # the Telegram sender currently in this chat must still be the
            # same person who authenticated the session. Access-code login
            # rebinds BotClient.telegram_user_id to whoever last logged in
            # with that code, so a management session opened earlier by a
            # different Telegram account must not keep acting as this
            # client once ownership has moved. Numeric Telegram user id is
            # the ownership identity — never compare on username. The
            # separate Activation Engine flow (H1F and earlier) resolves/
            # binds its own BotClient fresh at each activation step and is
            # untouched by H1G.
            if "activation_token" not in session:
                if _resolve_authenticated_bot_client(bot_client_id, from_user, db) is None:
                    _SESSIONS[chat_id] = {"state": "awaiting_code"}
                    await _send_message(chat_id, _H1G_SESSION_INVALID_TEXT)
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

        # UI3D-C1: reconcile assigned url/media slugs to Activated on every
        # successful access-code login (not gated to "first login only" —
        # see _reconcile_assigned_slug_activation for why retryability
        # matters). Best-effort — never blocks the client from reaching
        # their normal Bot menu below. The helper already guards each slug
        # individually; this outer guard is defense-in-depth so even a
        # totally unexpected failure (e.g. the assigned-slugs query itself)
        # can never stop the login response below — safe to retry on the
        # client's next access-code entry regardless.
        try:
            _reconcile_assigned_slug_activation(client, db)
        except Exception:
            logger.exception(
                "UI3D-C1 reconciliation raised unexpectedly for bot_client_id=%s "
                "— continuing login without blocking the client",
                client.id,
            )

        slugs = _get_active_assigned_slugs(client.id, db)
        if not slugs:
            _SESSIONS[chat_id] = {"state": "awaiting_code"}
            await _send_message(chat_id, "You're authenticated, but no active slugs are assigned to your account yet.")
            return

        if len(slugs) == 1:
            # A single assigned slug has nothing meaningful to "select" —
            # go straight to its management menu instead of a numbered
            # list whose only valid answer is "1".
            await _enter_slug_management_state(chat_id, client.id, slugs, slugs[0]["slug"], db)
            return

        await _enter_slug_list_state(chat_id, client.id, slugs)
        return

    if state == "awaiting_slug_selection":
        # This state is only ever entered by _enter_slug_list_state, which
        # never runs for zero-or-one-slug clients (see the login branch
        # above and _return_to_slug_list_or_login) — so `slugs` here always
        # has 2+ items and a numbered choice is always meaningful.
        slugs = session.get("slugs", [])
        idx = _parse_index(text, len(slugs))
        if idx is None:
            await _send_message(chat_id, f"Please reply with a number between 1 and {len(slugs)}.")
            return

        chosen = slugs[idx]
        await _enter_slug_management_state(
            chat_id, session["bot_client_id"], slugs, chosen["slug"], db
        )
        return

    if state == "awaiting_new_url":
        if text.lower() == "/cancel":
            await _send_message(chat_id, "Cancelled.")
            await _return_to_slug_list_or_login(chat_id, session)
            return
        normalized_url = _normalize_telegram_destination_url(text)
        if normalized_url is None:
            await _send_message(chat_id, "That doesn't look like a valid web URL. Send a domain such as example.com or a full http:// / https:// URL, then try again — or /cancel.")
            return
        if _is_blocked_destination_url(normalized_url):
            await _send_message(
                chat_id,
                "This link cannot be used because it points back to SHADZ or an internal address. "
                "Please send an external public link instead.",
            )
            return

        session["pending_value"] = normalized_url
        session["state"] = "awaiting_confirmation"
        _SESSIONS[chat_id] = session
        await _send_message(
            chat_id,
            f"Update '{session['selected_slug']}' destination to:\n{normalized_url}\n\n"
            "Tap Confirm to save it, Change to send a different URL, or Cancel to go back. "
            "(You can also reply YES or NO.)",
            reply_markup=_url_management_confirmation_markup(),
        )
        return

    if state == "awaiting_media_upload":
        if text.lower() == "/cancel":
            await _send_message(chat_id, "Cancelled.")
            await _return_to_slug_list_or_login(chat_id, session)
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
            # Pre-existing Phase 4M guard (unchanged) — a mid-upload type
            # change is out of scope for this fix; kept exactly as before
            # (see tests/test_bot_runtime.py).
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
        await _return_to_slug_list_or_login(chat_id, session)
        return

    if state == _URL_MANAGEMENT_CLAIMED_STATE:
        # Another action (an inline button or a typed YES/NO/CHANGE) is
        # already mid-flight for this exact pending confirmation —
        # _claim_url_management_context set this transient marker
        # synchronously and whichever caller claimed it is still running.
        # This state is never a real destination for a reply, so it must
        # never fall into the generic "Unknown/expired state" reset below,
        # which would clobber the in-flight claim's own session write out
        # from under it. Silently ignore; there is nothing safe to do
        # with this message.
        return

    if state == "awaiting_confirmation":
        # Typed compatibility fallback for the inline Confirm/Change/Cancel
        # buttons — routes through the exact same claim
        # (_claim_url_management_context) and action
        # (_apply_url_management_action) the button callback uses, so the
        # two entry points can never diverge: same idempotency rules, same
        # persistence/rollback/retry behaviour, same single/multi-slug
        # return behaviour. No callback object is faked and no callback
        # answer is sent — there is no Telegram callback here to answer.
        answer = text.lower()
        if answer in ("yes", "y", "confirm"):
            action = "confirm"
        elif answer in ("no", "n", "cancel"):
            action = "cancel"
        elif answer == "change":
            action = "change"
        else:
            await _send_message(chat_id, "Please reply YES to confirm or NO to cancel.")
            return

        claim = _claim_url_management_context(chat_id, from_user, db)
        if claim is _URL_MANAGEMENT_IDENTITY_INVALIDATED:
            await _send_message(chat_id, _H1G_SESSION_INVALID_TEXT)
            return
        if claim is None:
            await _send_message(chat_id, _URL_MANAGEMENT_UNAVAILABLE_TEXT)
            return
        await _apply_url_management_action(chat_id, action, claim, db)
        return

    if state == "awaiting_activation_confirmation":
        # Ordinary text here must never fall into Bot Client login — the
        # session (and its activation_token) is preserved untouched, and the
        # text is never treated as an access code.
        await _send_message(
            chat_id,
            activation_i18n.text(
                "CONFIRMATION_REMINDER", session.get("language", activation_i18n.DEFAULT_LANGUAGE)
            ),
        )
        return

    if state == _ACTIVATION_LANGUAGE_SELECT_STATE:
        # H1F: ordinary text while the language selector is showing must
        # never fall into Bot Client login either — re-validate the token
        # from scratch (same pattern as every other activation state) and
        # re-send the same selector (no language is known yet, so this
        # stays the neutral English prompt) rather than treating the text
        # as an access code or an implicit language choice.
        token = session.get("activation_token")
        record = _lookup_unactivated_record(token, db)
        markup = _activation_language_markup(token) if record else None
        if markup is None:
            _SESSIONS.pop(chat_id, None)
            await _send_message(chat_id, _ACTIVATION_INVALID_LINK_TEXT)
            return
        await _send_message(
            chat_id, activation_i18n.text("LANGUAGE_PROMPT", activation_i18n.DEFAULT_LANGUAGE), reply_markup=markup
        )
        return

    # Phase A5 replaces the former TEMPORARY handoff placeholder outright:
    # a session only still sits here (state == _ACTIVATION_SETUP_STATE with
    # confirmed_destination_url or confirmed_activation_media set) if an
    # earlier finalization attempt failed — a fresh Confirm now finalizes
    # immediately (see the webhook route and the typed-YES branch below).
    # Deliberately narrow: retrying only reuses the SAME existing UX each
    # content type already offers, rather than treating arbitrary chat text
    # as an implicit retry (which would re-attempt a Telegram
    # download/R2 upload on every unrelated "thanks"/"ok"). A url session
    # accepts the same typed YES/Y/Confirm keywords its own Confirm state
    # already recognises; a media session is button-only, matching A4M's
    # original design (no typed fallback) — any text there is just a
    # reminder to re-tap Confirm, never a retry trigger.
    if state == _ACTIVATION_SETUP_STATE and "confirmed_destination_url" in session:
        if text.lower() in ("yes", "y", "confirm"):
            await _finalize_activation_confirmation(chat_id, db)
            return
        await _send_message(
            chat_id,
            activation_i18n.text("FINALIZE_RETRY_URL", session.get("language", activation_i18n.DEFAULT_LANGUAGE)),
        )
        return
    if state == _ACTIVATION_SETUP_STATE and "confirmed_activation_media" in session:
        await _send_message(
            chat_id,
            activation_i18n.text("FINALIZE_RETRY_MEDIA", session.get("language", activation_i18n.DEFAULT_LANGUAGE)),
        )
        return

    if state in (_ACTIVATION_URL_INPUT_STATE, _ACTIVATION_URL_CONFIRM_STATE):
        # Re-validate the activation session from scratch on every message —
        # never trust that the token/record are still eligible just because
        # the session reached this state earlier (archived/activated since,
        # or a forged/stale session). Shared with the A4U callback handler
        # via _lookup_unactivated_url_link.
        token = session.get("activation_token")
        lang = session.get("language", activation_i18n.DEFAULT_LANGUAGE)
        link = _lookup_unactivated_url_link(token, db)
        if link is None:
            _SESSIONS.pop(chat_id, None)
            await _send_message(chat_id, activation_i18n.text("INVALID_LINK", lang))
            return

        if state == _ACTIVATION_URL_INPUT_STATE:
            normalized_url = _normalize_telegram_destination_url(text)
            if normalized_url is None:
                await _send_message(chat_id, activation_i18n.text("URL_INVALID_FORMAT", lang))
                return
            if _is_blocked_destination_url(normalized_url):
                await _send_message(chat_id, activation_i18n.text("URL_BLOCKED", lang))
                return

            # Normalized URL (Hotfix H1D) — trimmed, with a scheme
            # detected case-insensitively or "https://" prepended when
            # none was supplied. An explicitly supplied http:// or
            # https:// is preserved verbatim.
            session["pending_url"] = normalized_url
            session["state"] = _ACTIVATION_URL_CONFIRM_STATE
            _SESSIONS[chat_id] = session
            markup = _a4u_confirmation_markup(token, lang)
            await _send_message(
                chat_id,
                activation_i18n.text("URL_CONFIRM_PROMPT", lang, url=normalized_url),
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
                activation_i18n.text("URL_SAVED", lang, url=session["confirmed_destination_url"]),
            )
            # Phase A5: finalize immediately, in this same message — the
            # same function the webhook route calls after the inline
            # Confirm button, so both confirmation paths behave identically.
            await _finalize_activation_confirmation(chat_id, db)
            return
        if answer in ("no", "n", "change", "retry", "cancel"):
            session.pop("pending_url", None)
            session.pop("confirmed_destination_url", None)
            session["state"] = _ACTIVATION_URL_INPUT_STATE
            _SESSIONS[chat_id] = session
            await _send_message(chat_id, activation_i18n.text("URL_RETRY", lang))
            return
        await _send_message(chat_id, activation_i18n.text("URL_CONFIRM_INVALID_REPLY", lang))
        return

    if state in (_ACTIVATION_MEDIA_INPUT_STATE, _ACTIVATION_MEDIA_CONFIRM_STATE):
        # Re-validate the activation session from scratch on every message —
        # same rationale as the url branch above, shared via
        # _lookup_unactivated_media_link.
        token = session.get("activation_token")
        lang = session.get("language", activation_i18n.DEFAULT_LANGUAGE)
        link = _lookup_unactivated_media_link(token, db)
        if link is None:
            _SESSIONS.pop(chat_id, None)
            await _send_message(chat_id, activation_i18n.text("INVALID_LINK", lang))
            return

        if state == _ACTIVATION_MEDIA_CONFIRM_STATE:
            # A4M confirmation is inline-button-only (no typed YES/NO
            # fallback, unlike A4U) — any message here, text or media, is
            # unrelated input and must not corrupt the session.
            await _send_message(chat_id, activation_i18n.text("MEDIA_CONFIRM_REMINDER", lang))
            return

        # state == _ACTIVATION_MEDIA_INPUT_STATE
        #
        # A4M validates ONLY Telegram's own message metadata — it never
        # downloads the file (_download_telegram_file is not called here)
        # and never uploads or persists anything. The same
        # extraction/mime-allowlist/size checks T1C uses are reused so
        # supported formats/limits stay identical, but the outcome is a
        # plain in-memory dict, not a stored asset. Phase A5 owns the
        # actual download/upload/MediaAsset sequence.
        candidate = _extract_media_candidate(message)
        if candidate is None:
            await _send_message(chat_id, activation_i18n.text("MEDIA_UNSUPPORTED", lang))
            return

        file_id, mime_type, reported_size, file_name = candidate
        if not file_id:
            await _send_message(chat_id, activation_i18n.text("MEDIA_UNSUPPORTED", lang))
            return

        media_type = _media_type_for_mime(mime_type)
        if media_type is None:
            await _send_message(
                chat_id,
                activation_i18n.text("MEDIA_UNSUPPORTED_TYPE", lang, mime=mime_type or "unknown"),
            )
            return

        if reported_size is not None:
            # Reject a non-integer, boolean, or non-positive reported size
            # before ever consulting _MAX_TELEGRAM_MEDIA_BYTES — a
            # malformed Telegram payload must never produce pending
            # metadata with a nonsensical size. Uses the same generic
            # unsupported-media reply as the other input-side rejections
            # above, since this is likewise "not a usable file", not a
            # too-large file.
            if isinstance(reported_size, bool) or not isinstance(reported_size, int) or reported_size <= 0:
                await _send_message(chat_id, activation_i18n.text("MEDIA_UNSUPPORTED", lang))
                return
            if reported_size > _MAX_TELEGRAM_MEDIA_BYTES:
                await _send_message(
                    chat_id,
                    activation_i18n.text(
                        "MEDIA_TOO_LARGE",
                        lang,
                        size=reported_size // (1024 * 1024),
                        max=_MAX_TELEGRAM_MEDIA_BYTES // (1024 * 1024),
                    ),
                )
                return

        # Same fallback-filename convention T1C uses for a photo (which
        # never carries a Telegram file_name) — metadata only, no bytes
        # touched.
        safe_name = file_name or _default_filename(media_type, mime_type)

        session["pending_activation_media"] = {
            "telegram_file_id": file_id,
            "media_type": media_type,
            "mime_type": mime_type,
            "original_filename": safe_name,
            "file_size": reported_size,
        }
        session["state"] = _ACTIVATION_MEDIA_CONFIRM_STATE
        _SESSIONS[chat_id] = session
        markup = _a4m_confirmation_markup(token, lang)
        await _send_message(
            chat_id,
            activation_i18n.text("MEDIA_CONFIRM_PROMPT", lang, name=safe_name),
            reply_markup=markup,
        )
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
                if isinstance(cq_data, str) and cq_data.startswith(_ACTIVATION_LANG_PAYLOAD_PREFIX):
                    # H1F: distinct "actlang_" prefix — never touches the
                    # "activate_"/"a4uconfirm_"/etc. dispatch below.
                    await _handle_activation_language_callback(callback_query, db)
                elif isinstance(cq_data, str) and (
                    cq_data.startswith(_A4U_CONFIRM_PAYLOAD_PREFIX)
                    or cq_data.startswith(_A4U_CHANGE_PAYLOAD_PREFIX)
                ):
                    # Distinct prefix dispatch — never touches the A2/A3
                    # "activate_" callback path below.
                    await _handle_a4u_confirmation_callback(callback_query, db)
                    # Phase A5: runs immediately, in this same request — a
                    # no-op unless the session actually landed in
                    # _ACTIVATION_SETUP_STATE with confirmed content (i.e.
                    # only after a genuine Confirm, never a Change or a
                    # rejected/duplicate tap).
                    await _finalize_activation_confirmation(
                        _callback_chat_id(callback_query), db
                    )
                elif isinstance(cq_data, str) and (
                    cq_data.startswith(_A4M_CONFIRM_PAYLOAD_PREFIX)
                    or cq_data.startswith(_A4M_CHANGE_PAYLOAD_PREFIX)
                ):
                    await _handle_a4m_confirmation_callback(callback_query, db)
                    await _finalize_activation_confirmation(
                        _callback_chat_id(callback_query), db
                    )
                elif cq_data in (
                    _URL_MANAGEMENT_CONFIRM_CALLBACK,
                    _URL_MANAGEMENT_CHANGE_CALLBACK,
                    _URL_MANAGEMENT_CANCEL_CALLBACK,
                ):
                    # Distinct fixed literals — never touches the
                    # activation-engine callback paths above.
                    await _handle_url_management_confirmation_callback(callback_query, db)
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
