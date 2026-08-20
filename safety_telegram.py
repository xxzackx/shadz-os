"""Safety Engine v1 Phase S6 — Telegram delivery for early reminders,
missed-checkin alerts, late-checkin notices, and SOS escalation.

Delivery-retry correction: bot_runtime._send_message cannot be reused here
because it never reports whether the send actually succeeded — every path
through it (missing token, HTTP failure, network failure, or a genuine
success) returns None, by design, for its own BotClient-chat use case. Safety
needs an honest success/failure signal so a failed send can be retried and a
successful one is never repeated (see safety_notify.py's notified_at /
last_notified_at columns). Rather than change that shared, unrelated
BotClient helper, this module adds its own thin low-level sender
(_send_telegram_message) using the same TELEGRAM_BOT_TOKEN / httpx /
sendMessage conventions bot_runtime._send_message already uses (reusing its
_TELEGRAM_API_BASE constant directly rather than duplicating the URL
format), scoped entirely to Safety notifications.

Safety notifications are independent of the BotClient self-service runtime:
this module never reads or writes bot_runtime._SESSIONS or any other
BotClient/activation state.

SOS inline actions (urgent live-testing fix): send_sos_notification attaches
an ACKNOWLEDGE (status "open") or RESOLVE (status "acknowledged") inline
button, built by _sos_inline_keyboard purely from the emergency's current
status -- there is no separate UI-state tracked anywhere. The tap itself is
handled by bot_runtime._handle_sos_action_callback (SOS_ACK_CALLBACK_PREFIX /
SOS_RESOLVE_CALLBACK_PREFIX, exported from this module since it owns every
other SOS-message concern), which reuses safety_notify.acknowledge_sos /
resolve_sos exactly as safety_admin.py's admin routes do -- no parallel
lifecycle logic exists here, and the strict S7 open -> acknowledged ->
resolved transition (with its idempotency and TOCTOU handling) is untouched.
edit_sos_message then re-renders the tapped Telegram message via
editMessageText, swapping its keyboard to match the new status --
acknowledged gets the RESOLVE keyboard, and resolved gets an explicit
{"inline_keyboard": []} (never None/omission, which Telegram does not
treat as "remove the existing keyboard" on an edit -- see
_sos_inline_keyboard's for_edit parameter and edit_sos_message's own
docstring for why).

Phase S6.1 — recipient separation: S6 originally routed every Safety
notification to one shared SAFETY_TELEGRAM_CHAT_ID as a temporary stand-in.
The locked routing is now:
  - early_reminder   -> the target SafetyUser's own telegram_chat_id
                         (models.SafetyUser.telegram_chat_id, see
                         _user_chat_id). Missing/invalid -> logged and
                         returns False; NEVER falls back to the Admin
                         recipient or another user.
  - missed_checkin, late_checkin, sos, sos escalation
                     -> SHADZ Admin, i.e. SAFETY_TELEGRAM_CHAT_ID (see
                         _admin_chat_id). This is a fixed operational
                         destination, never a SafetyUser's own chat id.
These two resolvers are deliberately kept separate (not a single "resolve a
chat id" function with a fallback) so an Admin-directed send can never
accidentally read a user's telegram_chat_id, and a user-directed reminder
can never accidentally fall back to Admin.

Every public send function here is best-effort and never raises: any
failure (missing/invalid chat id, missing token, HTTP error, network error,
or an unexpected exception) is logged and the function returns False. That
keeps one failing notification from ever being able to abort delivery of
any other notification in the same batch — main.py's notify loop can simply
await each send_* call in turn with no per-call try/except of its own
needed for that guarantee. The caller only ever marks a notification
delivered (safety_notify.mark_alert_notified / mark_sos_notified /
mark_late_checkin_notified) after seeing True come back here — never
speculatively, and never as a side effect of a DB claim. GPS/Maps content is
only ever built from persisted latitude/longitude — there is no path that
fabricates or guesses a location.
"""
import logging
import os

import httpx

import bot_runtime
import models  # noqa: F401 -- referenced only in string type hints below

logger = logging.getLogger("safety_telegram")


def _admin_chat_id() -> int | None:
    """SHADZ Admin's Telegram recipient — used for missed-checkin,
    late-checkin, SOS, and SOS-escalation notifications. Never used for an
    early reminder (see _user_chat_id for that)."""
    raw = os.environ.get("SAFETY_TELEGRAM_CHAT_ID", "")
    if not raw:
        logger.error(
            "SAFETY_TELEGRAM_CHAT_ID is not configured — cannot send Safety "
            "Admin Telegram notification"
        )
        return None
    try:
        return int(raw)
    except ValueError:
        logger.error("SAFETY_TELEGRAM_CHAT_ID is not a valid integer chat id")
        return None


def _user_chat_id(user: "models.SafetyUser") -> int | None:
    """A SafetyUser's own Telegram recipient — used for early reminders
    only. Missing/invalid is logged and returns None; the caller must never
    substitute the Admin recipient or any other user's chat id for it."""
    chat_id = user.telegram_chat_id
    if chat_id is None:
        logger.error(
            "SafetyUser id=%s has no telegram_chat_id configured — cannot "
            "send early reminder",
            user.id,
        )
        return None
    return chat_id


def maps_link(latitude: float | None, longitude: float | None) -> str | None:
    """A Google Maps link built only from persisted coordinates — None
    (never a fabricated/placeholder link) when either is missing."""
    if latitude is None or longitude is None:
        return None
    return f"https://maps.google.com/?q={latitude},{longitude}"


# Telegram inline-button callback_data prefixes for SOS actions. Public
# (no leading underscore) because bot_runtime's webhook dispatch imports
# these to route a tapped button to _handle_sos_action_callback -- kept
# here rather than in bot_runtime.py since this module already owns every
# other SOS-message concern (formatting, chat routing, sending).
SOS_ACK_CALLBACK_PREFIX = "sos_ack:"
SOS_RESOLVE_CALLBACK_PREFIX = "sos_resolve:"


def _sos_inline_keyboard(
    emergency_id: int, status: str, *, for_edit: bool = False
) -> dict | None:
    """The inline keyboard attached to an SOS Telegram message, driven only
    by the emergency's current status -- there is no separately tracked UI
    state, so this can never drift from the real S7 lifecycle:
      open         -> ACKNOWLEDGE button
      acknowledged -> RESOLVE button
      resolved (or anything else):
        - for_edit=False (the initial sendMessage call in
          send_sos_notification): None -- there is no prior keyboard on a
          brand-new message, and collect_due_sos_notifications never
          selects an already-resolved emergency anyway (see
          _SOS_ESCALATION_STATUSES), so this path never actually runs for
          "resolved" today; None is simply "no keyboard on send", which
          sendMessage accepts by omitting reply_markup entirely.
        - for_edit=True (_handle_sos_action_callback's editMessageText
          call, after resolve_sos succeeds): an explicit
          {"inline_keyboard": []}. Telegram's editMessageText does NOT
          remove an existing keyboard when reply_markup is left out of the
          request -- it only removes/replaces one when reply_markup is
          present, so an already-sent ACKNOWLEDGE/RESOLVE keyboard must be
          overwritten with this explicit empty keyboard, never by omission.
    """
    if status == "open":
        return {
            "inline_keyboard": [[
                {"text": "ACKNOWLEDGE", "callback_data": f"{SOS_ACK_CALLBACK_PREFIX}{emergency_id}"}
            ]]
        }
    if status == "acknowledged":
        return {
            "inline_keyboard": [[
                {"text": "RESOLVE", "callback_data": f"{SOS_RESOLVE_CALLBACK_PREFIX}{emergency_id}"}
            ]]
        }
    if for_edit:
        return {"inline_keyboard": []}
    return None


async def _send_telegram_message(
    chat_id: int, text: str, reply_markup: dict | None = None
) -> bool:
    """Low-level Safety sendMessage call with an honest success signal.

    Mirrors bot_runtime._send_message's token lookup / httpx / sendMessage
    call, but returns an honest success signal instead of silently
    swallowing failure -- that's the entire reason this exists instead of
    reusing bot_runtime._send_message. Never raises.

    A 2xx HTTP status alone is NOT proof Telegram accepted the message --
    the Bot API always replies with a JSON body of the form
    {"ok": bool, ...}, and only {"ok": true} is a confirmed success. So
    True is returned only when the response is valid JSON, is a JSON
    object, and that object's "ok" key is exactly True. Every other case
    (missing token, HTTP error, network error, unparseable body, or a 2xx
    response with "ok" false/absent) returns False -- the caller's DB claim
    stays untouched, keeping the notification retryable.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        logger.error(
            "TELEGRAM_BOT_TOKEN is not configured — cannot send Safety "
            "Telegram notification to chat_id=%s",
            chat_id,
        )
        return False
    url = bot_runtime._TELEGRAM_API_BASE.format(token=token) + "/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # Never interpolate/stringify exc — see bot_runtime._send_message's
        # identical guard: httpx's auto-generated message embeds the full
        # request URL, and Telegram's Bot API puts the token in the URL
        # path (no header/query param to redact instead).
        logger.error(
            "Failed to send Safety Telegram message to chat_id=%s: HTTP %s (%s)",
            chat_id, exc.response.status_code, type(exc).__name__,
        )
        return False
    except httpx.HTTPError as exc:
        logger.error(
            "Failed to send Safety Telegram message to chat_id=%s: %s",
            chat_id, type(exc).__name__,
        )
        return False

    try:
        body = response.json()
    except ValueError:
        logger.error(
            "Safety Telegram sendMessage to chat_id=%s returned a non-JSON "
            "response body",
            chat_id,
        )
        return False

    if not isinstance(body, dict) or body.get("ok") is not True:
        logger.error(
            "Safety Telegram sendMessage to chat_id=%s was not confirmed "
            "successful by the Bot API",
            chat_id,
        )
        return False

    return True


async def _send(text: str, chat_id: int | None, reply_markup: dict | None = None) -> bool:
    """Send to an already-resolved destination chat id, catching any
    unexpected exception defensively (on top of _send_telegram_message's
    own internal handling) so a caller can always await send_early_reminder
    / send_missed_checkin_alert / send_late_checkin_alert /
    send_sos_notification without a try/except of its own and without
    risking the loop that processes a batch of due notifications ever being
    aborted by one bad send.

    chat_id resolution is deliberately the caller's job (_admin_chat_id vs
    _user_chat_id) rather than this function's -- see the module docstring
    for why the two resolvers are kept separate instead of one with a
    fallback."""
    if chat_id is None:
        return False
    try:
        if reply_markup is not None:
            return await _send_telegram_message(chat_id, text, reply_markup=reply_markup)
        # Omit the kwarg entirely (rather than passing reply_markup=None)
        # for every non-SOS send, so send_early_reminder/
        # send_missed_checkin_alert/send_late_checkin_alert keep their
        # exact pre-existing call shape -- only SOS attaches a keyboard.
        return await _send_telegram_message(chat_id, text)
    except Exception:
        logger.exception("Unexpected error sending Safety Telegram message to chat_id=%s", chat_id)
        return False


async def edit_sos_message(
    chat_id: int, message_id: int, text: str, reply_markup: dict | None
) -> bool:
    """Edit a previously-sent SOS Telegram message (editMessageText) after
    an inline Acknowledge/Resolve tap, to reflect the emergency's new
    status and swap/remove its inline keyboard in the same call --
    Telegram's editMessageText accepts reply_markup directly, so no
    separate editMessageReplyMarkup call is needed.

    IMPORTANT: reply_markup=None here means "omit the key from the
    request", and Telegram does NOT remove an already-attached keyboard
    when the key is simply absent from an editMessageText call -- it only
    changes the keyboard when reply_markup is present in the request. To
    actually remove a keyboard (the resolved case), the caller must pass
    an explicit {"inline_keyboard": []}, not None -- see
    _sos_inline_keyboard(..., for_edit=True), which is exactly why that
    parameter exists. None should only ever be passed here when there was
    never a keyboard to remove in the first place.

    Same honest fail-closed True/False contract as _send_telegram_message
    (only a confirmed {"ok": true} response counts as success); this is a
    parallel, independently-structured low-level sender rather than a
    shared refactor of _send_telegram_message, matching this module's
    existing convention of one thin function per Bot API method (see the
    module docstring on why bot_runtime._send_message isn't reused
    either). Never raises -- a failed edit is logged and simply leaves the
    Telegram message showing its prior (still-accurate-enough) text; it
    never blocks or reverses the already-committed acknowledge_sos/
    resolve_sos transition that triggered this call.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    if not token:
        logger.error(
            "TELEGRAM_BOT_TOKEN is not configured — cannot edit Safety "
            "Telegram message chat_id=%s message_id=%s",
            chat_id, message_id,
        )
        return False
    url = bot_runtime._TELEGRAM_API_BASE.format(token=token) + "/editMessageText"
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text}
    if reply_markup is not None:
        payload["reply_markup"] = reply_markup
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Failed to edit Safety Telegram message chat_id=%s message_id=%s: "
            "HTTP %s (%s)",
            chat_id, message_id, exc.response.status_code, type(exc).__name__,
        )
        return False
    except httpx.HTTPError as exc:
        logger.error(
            "Failed to edit Safety Telegram message chat_id=%s message_id=%s: %s",
            chat_id, message_id, type(exc).__name__,
        )
        return False

    try:
        body = response.json()
    except ValueError:
        logger.error(
            "Safety Telegram editMessageText chat_id=%s message_id=%s returned "
            "a non-JSON response body",
            chat_id, message_id,
        )
        return False

    if not isinstance(body, dict) or body.get("ok") is not True:
        logger.error(
            "Safety Telegram editMessageText chat_id=%s message_id=%s was not "
            "confirmed successful by the Bot API",
            chat_id, message_id,
        )
        return False

    return True


def _format_early_reminder(user: "models.SafetyUser") -> str:
    return (
        "⏰ Reminder: You haven’t checked in yet today.\n"
        f"• Daily deadline: {user.daily_deadline.strftime('%H:%M')} ({user.timezone})."
    )


def _format_missed_checkin(
    user: "models.SafetyUser",
    daily_state: "models.SafetyDailyState",
    last_checkin: "models.SafetyCheckIn | None",
) -> str:
    lines = [
        f"🔴 Missed check-in: {user.display_name}",
        f"Safety date: {daily_state.safety_date.isoformat()}",
        f"Deadline: {daily_state.deadline_utc.isoformat()} UTC",
    ]
    if last_checkin is not None:
        lines.append(f"Last known check-in: {last_checkin.checked_in_at.isoformat()} UTC")
        link = maps_link(last_checkin.latitude, last_checkin.longitude)
        if link:
            lines.append(f"Last known location: {link}")
    else:
        lines.append("No prior check-in on record.")
    return "\n".join(lines)


_SOS_STATUS_LABELS = {"open": "OPEN", "acknowledged": "ACKNOWLEDGED", "resolved": "RESOLVED"}


def _format_sos(user: "models.SafetyUser", emergency: "models.SafetyEmergency") -> str:
    """Shared by both the initial SOS send and every later
    _handle_sos_action_callback editMessageText call, so the Status line
    always reflects emergency.status at the moment this is called -- there
    is no separate "acknowledged text" / "resolved text" template to keep
    in sync."""
    lines = [
        "🚨 SOS EMERGENCY 🚨",
        f"{user.display_name} has triggered an emergency alert.",
        f"Triggered at: {emergency.triggered_at.isoformat()} UTC",
        f"Status: {_SOS_STATUS_LABELS.get(emergency.status, emergency.status.upper())}",
    ]
    link = maps_link(emergency.latitude, emergency.longitude)
    lines.append(f"Location: {link}" if link else "Location: not available")
    return "\n".join(lines)


def _format_late_checkin(
    user: "models.SafetyUser",
    checkin: "models.SafetyCheckIn",
    alert: "models.SafetyLateCheckinAlert",
) -> str:
    lines = [
        f"🟡 Late check-in: {user.display_name}",
        f"Safety date: {alert.safety_date.isoformat()}",
        f"Checked in at: {checkin.checked_in_at.isoformat()} UTC (after deadline)",
    ]
    link = maps_link(checkin.latitude, checkin.longitude)
    if link:
        lines.append(f"Location: {link}")
    return "\n".join(lines)


async def send_early_reminder(user: "models.SafetyUser") -> bool:
    """True only on confirmed delivery — callers must only mark this
    notification's SafetyAlert.notified_at when this returns True.

    Always routes to the SafetyUser's own telegram_chat_id — never the
    Admin recipient (see _user_chat_id)."""
    return await _send(_format_early_reminder(user), _user_chat_id(user))


async def send_missed_checkin_alert(
    user: "models.SafetyUser",
    daily_state: "models.SafetyDailyState",
    last_checkin: "models.SafetyCheckIn | None",
) -> bool:
    """True only on confirmed delivery — callers must only mark this
    notification's SafetyAlert.notified_at when this returns True.

    Always routes to SHADZ Admin — never the target SafetyUser's own
    telegram_chat_id (see _admin_chat_id)."""
    return await _send(_format_missed_checkin(user, daily_state, last_checkin), _admin_chat_id())


async def send_late_checkin_alert(
    user: "models.SafetyUser",
    checkin: "models.SafetyCheckIn",
    alert: "models.SafetyLateCheckinAlert",
) -> bool:
    """True only on confirmed delivery — callers must only call
    safety_notify.mark_late_checkin_notified when this returns True.

    Always routes to SHADZ Admin — never the target SafetyUser's own
    telegram_chat_id (see _admin_chat_id)."""
    return await _send(_format_late_checkin(user, checkin, alert), _admin_chat_id())


async def send_sos_notification(
    user: "models.SafetyUser", emergency: "models.SafetyEmergency"
) -> bool:
    """True only on confirmed delivery — callers must only call
    safety_notify.mark_sos_notified when this returns True.

    Always routes to SHADZ Admin — never the target SafetyUser's own
    telegram_chat_id (see _admin_chat_id). Attaches the ACKNOWLEDGE inline
    button whenever emergency.status is still "open" at send time
    (_sos_inline_keyboard) -- every escalation retry re-sends this while
    still open, so each such message carries a working button, not just
    the very first one."""
    return await _send(
        _format_sos(user, emergency),
        _admin_chat_id(),
        reply_markup=_sos_inline_keyboard(emergency.id, emergency.status),
    )
