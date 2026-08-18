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


async def _send_telegram_message(chat_id: int, text: str) -> bool:
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


async def _send(text: str, chat_id: int | None) -> bool:
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
        return await _send_telegram_message(chat_id, text)
    except Exception:
        logger.exception("Unexpected error sending Safety Telegram message to chat_id=%s", chat_id)
        return False


def _format_early_reminder(user: "models.SafetyUser") -> str:
    return (
        f"⏰ Reminder: {user.display_name} hasn't checked in yet today.\n"
        f"Daily deadline: {user.daily_deadline.strftime('%H:%M')} ({user.timezone})."
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


def _format_sos(user: "models.SafetyUser", emergency: "models.SafetyEmergency") -> str:
    lines = [
        "🚨 SOS EMERGENCY 🚨",
        f"{user.display_name} has triggered an emergency alert.",
        f"Triggered at: {emergency.triggered_at.isoformat()} UTC",
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
    telegram_chat_id (see _admin_chat_id)."""
    return await _send(_format_sos(user, emergency), _admin_chat_id())
