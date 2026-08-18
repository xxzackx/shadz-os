import asyncio
import logging
import os
import secrets
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

import models
from database import Base, SessionLocal, engine, get_db
from link_admin import register_link_admin_routes
from media_admin import register_media_admin_routes
from page_admin import register_page_admin_routes
from page_public import serve_public_page
from link_public import expired_page_response, resolve_activation_redirect, serve_public_media
from safety_public import (
    SafetyCheckInResponse,
    SafetyGPSPayload,
    SafetySOSResponse,
    serve_safety_entry,
    submit_check_in,
    submit_sos,
)
from safety_deadline import evaluate_all_active_users
import safety_telegram
from safety_notify import (
    collect_due_early_reminders,
    collect_due_late_checkin_alerts,
    collect_due_missed_alerts,
    collect_due_sos_notifications,
    last_checkin_before,
    mark_alert_notified,
    mark_late_checkin_notified,
    mark_sos_notified,
    release_alert_delivery_claim,
    release_late_checkin_delivery_claim,
    release_sos_delivery_claim,
)
from nfc_legacy import register_nfc_routes, register_nfc_admin_routes
from bot_admin import register_bot_admin_routes
from bot_runtime import register_bot_webhook_routes
from safety_admin import register_safety_admin_routes

Base.metadata.create_all(bind=engine)


def _run_migrations() -> None:
    """Safe additive migrations for existing production SQLite tables.

    Base.metadata.create_all never adds columns to an existing table, so we
    inspect PRAGMA table_info and ALTER TABLE ADD COLUMN for any column that
    is missing.  Running this multiple times is harmless — it skips columns
    that already exist.  Tables that do not yet exist are skipped entirely
    (PRAGMA returns an empty list for a non-existent table).

    Covers: redirect_links, media_assets.  No Alembic required.
    """
    redirect_links_cols = {
        "content_type": "VARCHAR",
        "client_name":  "VARCHAR",
        "phone_number": "VARCHAR",
        "notes":        "TEXT",
        "is_archived":  "BOOLEAN",
        "archived_at":  "DATETIME",
    }
    media_assets_cols = {
        "display_name": "VARCHAR",
    }
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA table_info(redirect_links)")).fetchall()
        existing = {row[1] for row in rows}
        for col, col_type in redirect_links_cols.items():
            if col not in existing:
                conn.execute(text(
                    f"ALTER TABLE redirect_links ADD COLUMN {col} {col_type}"
                ))

        rows = conn.execute(text("PRAGMA table_info(media_assets)")).fetchall()
        if rows:
            existing = {row[1] for row in rows}
            for col, col_type in media_assets_cols.items():
                if col not in existing:
                    conn.execute(text(
                        f"ALTER TABLE media_assets ADD COLUMN {col} {col_type}"
                    ))

        # ── Page Engine v1 — pages ───────────────────────────────────────────
        # create_all handles new table creation; this block guards future
        # additive column additions and confirms the table is present.
        # All ALTER TABLE definitions are nullable or carry a DEFAULT so they
        # are safe if the table already has rows.  NOT NULL strictness is
        # enforced at the ORM/application layer, not here.
        pages_cols = {
            "title":         "VARCHAR",
            "template_type": "VARCHAR",
            "status":        "VARCHAR DEFAULT 'draft'",
            "content_json":  "TEXT",
            "created_at":    "DATETIME",
            "updated_at":    "DATETIME",
            "archived_at":   "DATETIME",
        }
        rows = conn.execute(text("PRAGMA table_info(pages)")).fetchall()
        if rows:
            existing = {row[1] for row in rows}
            for col, col_type in pages_cols.items():
                if col not in existing:
                    conn.execute(text(
                        f"ALTER TABLE pages ADD COLUMN {col} {col_type}"
                    ))

        # ── Page Engine v1 — page_slug_attachments ───────────────────────────
        # Same safety rule: all ALTER TABLE definitions are nullable or carry
        # a DEFAULT.  Strict constraints live at the ORM/application layer.
        psa_cols = {
            "page_id":    "INTEGER",
            "slug":       "VARCHAR",
            "is_active":  "BOOLEAN DEFAULT 1",
            "created_at": "DATETIME",
            "updated_at": "DATETIME",
        }
        rows = conn.execute(text("PRAGMA table_info(page_slug_attachments)")).fetchall()
        if rows:
            existing = {row[1] for row in rows}
            for col, col_type in psa_cols.items():
                if col not in existing:
                    conn.execute(text(
                        f"ALTER TABLE page_slug_attachments ADD COLUMN {col} {col_type}"
                    ))

        # ── UI3D-C1 Polish — bot_clients.telegram_display_name ──────────────
        # Nullable additive column, same safe pattern as above. Display
        # metadata only — never used for identity/matching.
        bot_clients_cols = {
            "telegram_display_name": "VARCHAR",
        }
        rows = conn.execute(text("PRAGMA table_info(bot_clients)")).fetchall()
        if rows:
            existing = {row[1] for row in rows}
            for col, col_type in bot_clients_cols.items():
                if col not in existing:
                    conn.execute(text(
                        f"ALTER TABLE bot_clients ADD COLUMN {col} {col_type}"
                    ))

        # Normal indexes are declared via index=True on the model columns and
        # created by create_all.  Only the partial unique index is explicit here
        # because SQLAlchemy cannot express WHERE-clause indexes in mapped_column.
        # Partial unique index: only one active attachment per slug.
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_page_slug_one_active "
            "ON page_slug_attachments(slug) WHERE is_active = 1"
        ))

        # ── Safety Engine v1 Phase S2 — safety_users.secure_token ───────────
        # Additive column, added nullable (SQLite ALTER TABLE cannot attach a
        # UNIQUE constraint inline). Column-add, backfill, and index-creation
        # are each independently checked and applied on every run — not
        # gated behind "did we just add the column" — so the migration
        # recovers cleanly no matter which step a prior run stopped after
        # (e.g. process killed between ALTER TABLE and backfill).
        rows = conn.execute(text("PRAGMA table_info(safety_users)")).fetchall()
        if rows:
            existing = {row[1] for row in rows}
            if "secure_token" not in existing:
                conn.execute(text(
                    "ALTER TABLE safety_users ADD COLUMN secure_token VARCHAR"
                ))

            unbackfilled = conn.execute(text(
                "SELECT id FROM safety_users WHERE secure_token IS NULL OR secure_token = ''"
            )).fetchall()
            for row in unbackfilled:
                conn.execute(
                    text("UPDATE safety_users SET secure_token = :token WHERE id = :id"),
                    {"token": secrets.token_urlsafe(32), "id": row[0]},
                )

            # Only create the explicit index if no unique index already
            # covers secure_token alone — create_all() may already have
            # built one via the ORM column's unique=True/index=True on a
            # brand-new table (auto-named ix_safety_users_secure_token);
            # creating a second one here would just duplicate it.
            index_rows = conn.execute(text("PRAGMA index_list(safety_users)")).fetchall()
            has_unique_secure_token_index = False
            for idx_row in index_rows:
                idx_name, is_unique = idx_row[1], idx_row[2]
                if not is_unique:
                    continue
                idx_cols = conn.execute(text(f"PRAGMA index_info({idx_name})")).fetchall()
                if [c[2] for c in idx_cols] == ["secure_token"]:
                    has_unique_secure_token_index = True
                    break
            if not has_unique_secure_token_index:
                conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_safety_users_secure_token "
                    "ON safety_users(secure_token)"
                ))

            # ── Safety Engine v1 Phase S6.1 — safety_users.telegram_chat_id ──
            # Additive, nullable column: this SafetyUser's own Telegram
            # recipient for early reminders (see models.SafetyUser and
            # safety_telegram._user_chat_id). Left NULL on every existing
            # row -- no backfill possible or needed, a user with no chat id
            # configured simply never gets an early reminder sent (never
            # falls back to the Admin recipient).
            if "telegram_chat_id" not in existing:
                conn.execute(text(
                    "ALTER TABLE safety_users ADD COLUMN telegram_chat_id INTEGER"
                ))

        # ── Safety Engine v1 Phase S6 — Telegram notify additions ───────────
        # safety_emergencies.last_notified_at / notification_claimed_at:
        # additive, nullable columns driving the SOS retry/escalation
        # cadence and the concurrent-delivery lease (see safety_notify.py).
        rows = conn.execute(text("PRAGMA table_info(safety_emergencies)")).fetchall()
        if rows:
            existing = {row[1] for row in rows}
            if "last_notified_at" not in existing:
                conn.execute(text(
                    "ALTER TABLE safety_emergencies ADD COLUMN last_notified_at DATETIME"
                ))
            if "notification_claimed_at" not in existing:
                conn.execute(text(
                    "ALTER TABLE safety_emergencies ADD COLUMN notification_claimed_at DATETIME"
                ))

        # safety_alerts.notified_at / delivery_claimed_at: additive,
        # nullable columns separating "alert claimed" (row exists) from
        # "alert successfully delivered" and from "a worker currently holds
        # the delivery lease" (see safety_notify.py) — a Telegram failure
        # never has to delete or rewrite the row, it just leaves
        # notified_at NULL (and delivery_claimed_at released) for the next
        # tick to retry.
        rows = conn.execute(text("PRAGMA table_info(safety_alerts)")).fetchall()
        if rows:
            existing = {row[1] for row in rows}
            if "notified_at" not in existing:
                conn.execute(text(
                    "ALTER TABLE safety_alerts ADD COLUMN notified_at DATETIME"
                ))
            if "delivery_claimed_at" not in existing:
                conn.execute(text(
                    "ALTER TABLE safety_alerts ADD COLUMN delivery_claimed_at DATETIME"
                ))

            # Unique index enforcing the one-shot (user, safety_date,
            # alert_type) claim used by safety_notify._get_or_create_alert.
            # IF NOT EXISTS makes this idempotent whether create_all already
            # built it (brand-new table) or this is the first run against an
            # existing table. Fail closed instead of creating it blind: if
            # pre-S6 data somehow already contains duplicate
            # (user_id, safety_date, alert_type) rows, SQLite would refuse
            # the CREATE UNIQUE INDEX anyway with an opaque error — detect
            # that case ourselves first and raise a clear, actionable
            # message rather than silently deduping or leaving the app to
            # crash on a cryptic IntegrityError deep in a migration.
            dupes = conn.execute(text(
                "SELECT user_id, safety_date, alert_type, COUNT(*) AS n "
                "FROM safety_alerts "
                "GROUP BY user_id, safety_date, alert_type "
                "HAVING COUNT(*) > 1"
            )).fetchall()
            if dupes:
                raise RuntimeError(
                    "Cannot create uq_safety_alerts_user_date_type: "
                    f"{len(dupes)} existing duplicate (user_id, safety_date, "
                    "alert_type) group(s) found in safety_alerts "
                    f"(e.g. {tuple(dupes[0])}). Refusing to silently dedupe "
                    "historical Safety data -- resolve these rows manually, "
                    "then restart."
                )
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_safety_alerts_user_date_type "
                "ON safety_alerts(user_id, safety_date, alert_type)"
            ))

        conn.commit()


_run_migrations()

app = FastAPI(title="Shadz OS", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["*", "X-API-Key"],
)


# ---------------------------------------------------------------------------
# Auth — HTTP Basic (SHADZ Admin Core)
# Protects all /admin/* routes via the admin_router dependency.
# Credentials are read from ADMIN_USERNAME and ADMIN_PASSWORD env vars.
# Browser shows native login popup on first visit to /admin.
# ---------------------------------------------------------------------------

_http_basic = HTTPBasic()


def verify_admin(credentials: HTTPBasicCredentials = Depends(_http_basic)) -> str:
    """Reusable dependency for all SHADZ admin routes.

    - Reads ADMIN_USERNAME / ADMIN_PASSWORD from environment at call time.
    - Uses secrets.compare_digest to prevent timing-based attacks.
    - Returns the authenticated username on success.
    - Raises 401 with WWW-Authenticate header on failure (triggers browser popup).
    - Raises 500 if credentials are not configured on the server.
    """
    username = os.environ.get("ADMIN_USERNAME", "")
    password = os.environ.get("ADMIN_PASSWORD", "")

    if not username or not password:
        raise HTTPException(
            status_code=500,
            detail="Admin credentials are not configured on this server",
        )

    username_ok = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        username.encode("utf-8"),
    )
    password_ok = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        password.encode("utf-8"),
    )

    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=401,
            detail="Invalid admin credentials",
            headers={"WWW-Authenticate": 'Basic realm="SHADZ Admin"'},
        )

    return credentials.username


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Paths that must never be handled by the /{slug} dynamic redirect route.
# FastAPI's registration order already protects these, but this guard makes
# the protection explicit and survives any future route reordering.
RESERVED_SLUGS: frozenset[str] = frozenset({
    "admin",
    "health",
    "status",
    "run-command",
    "nfc",
    "r",
    "safety",
    "docs",         # FastAPI auto-generated OpenAPI UI
    "redoc",        # FastAPI auto-generated ReDoc UI
    "openapi.json",
})

# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Public health check — no auth required."""
    return {"status": "ok"}


@app.get("/", include_in_schema=False)
def home():
    """SHADZ public front page."""
    return FileResponse("static/index.html")


# NFC and legacy utility routes live in nfc_legacy.py — registered here.
# Must be registered before the /{slug} catch-all.
register_nfc_routes(app)

# Telegram Bot webhook route lives in bot_runtime.py — registered here.
# Must be registered before the /{slug} catch-all.
register_bot_webhook_routes(app)


@app.get("/safety/c/{secure_token}")
def safety_entry(secure_token: str, db: Session = Depends(get_db)):
    """Safety Engine v1 Phase S2 — public NFC-originated entry point.

    Render-only: resolves an active SafetyUser by secure_token and shows the
    minimal identity shell. No check-in/GPS/SOS behaviour — those are later
    phases. Unknown token and inactive-user token return an identical 404.
    """
    return serve_safety_entry(secure_token, db)


@app.post("/safety/c/{secure_token}/check-in", response_model=SafetyCheckInResponse)
def safety_check_in(
    secure_token: str, payload: SafetyGPSPayload, db: Session = Depends(get_db)
):
    """Safety Engine v1 Phase S4 — secure server-side I'M SAFE submission.

    Resolves the SafetyUser from secure_token only (never a client-supplied
    user id), validates the GPS payload, and persists a SafetyCheckIn with a
    server-generated timestamp. Unknown/inactive token returns the same 404
    as the GET entry route.
    """
    return submit_check_in(secure_token, payload, db)


@app.post("/safety/c/{secure_token}/sos", response_model=SafetySOSResponse)
def safety_sos(
    secure_token: str, payload: SafetyGPSPayload, db: Session = Depends(get_db)
):
    """Safety Engine v1 Phase S4 — secure server-side SOS submission.

    Resolves the SafetyUser from secure_token only, validates the GPS
    payload, and persists an open SafetyEmergency with a server-generated
    timestamp. Unknown/inactive token returns the same 404 as the GET entry
    route.
    """
    return submit_sos(secure_token, payload, db)


# ---------------------------------------------------------------------------
# Safety Engine v1 Phase S5 — Daily Safety State / Deadline Engine
#
# Periodic trigger only. SafetyDailyState in the DB is the sole authority —
# this loop just calls the idempotent evaluator on an interval so a missed
# deadline is detected in bounded time; a missed tick or a restart never
# loses correctness, the next tick (or the next check-in) re-derives the
# right state from scratch. Running multiple SHADZ processes is likewise
# safe: evaluate_user_deadline's transitions are conditional UPDATEs guarded
# by the (user_id, safety_date) unique constraint, so duplicate/overlapping
# triggers are idempotent no-ops, never double-transitions.
# ---------------------------------------------------------------------------

_safety_deadline_logger = logging.getLogger("safety_deadline_loop")
_SAFETY_DEADLINE_EVAL_INTERVAL_SECONDS = 60
_safety_deadline_task: asyncio.Task | None = None


def _run_safety_deadline_eval_tick() -> None:
    """Synchronous DB work for one tick — run via asyncio.to_thread so it
    never blocks the FastAPI event loop while evaluating."""
    db = SessionLocal()
    try:
        evaluate_all_active_users(db)
    finally:
        db.close()


async def _safety_deadline_eval_loop() -> None:
    try:
        while True:
            try:
                await asyncio.to_thread(_run_safety_deadline_eval_tick)
            except Exception:
                _safety_deadline_logger.exception("safety deadline eval loop tick failed")
            await asyncio.sleep(_SAFETY_DEADLINE_EVAL_INTERVAL_SECONDS)
    except asyncio.CancelledError:
        raise


@app.on_event("startup")
async def _start_safety_deadline_eval_loop() -> None:
    global _safety_deadline_task
    _safety_deadline_task = asyncio.create_task(_safety_deadline_eval_loop())


@app.on_event("shutdown")
async def _stop_safety_deadline_eval_loop() -> None:
    if _safety_deadline_task is None:
        return
    _safety_deadline_task.cancel()
    try:
        await _safety_deadline_task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# Safety Engine v1 Phase S6 — Telegram Reminder + Missed Alert + SOS
# Escalation
#
# A second, independent periodic loop. It never re-derives deadline/day
# state — it only reads what S5's SafetyDailyState (and S4's
# SafetyEmergency) already authoritatively recorded, via safety_notify.py's
# collectors.
#
# Delivery-retry correction: claiming a notification (a SafetyAlert row
# existing, or an open SafetyEmergency being selected) and successfully
# delivering it to Telegram are two separate steps here, deliberately never
# conflated:
#   - collect_due_* only ever reads/claims rows (a SafetyAlert row's mere
#     existence, or an open SafetyEmergency's eligibility) — it never marks
#     anything "delivered".
#   - Each safety_telegram.send_* call below returns an honest True/False
#     for whether Telegram actually accepted it (see safety_telegram.py's
#     docstring for why bot_runtime._send_message can't be reused for
#     this), and mark_alert_notified / mark_sos_notified is only ever
#     called when that came back True.
#   - So a missed tick, a restart, a Telegram outage, or a missing
#     SAFETY_TELEGRAM_CHAT_ID simply leaves the row unmarked — it stays (or
#     becomes) due again on the very next tick, with no separate retry
#     bookkeeping needed. Once successfully delivered, the same
#     unique-constrained claim (SafetyAlert) or conditional UPDATE
#     (SafetyEmergency.last_notified_at) that made the row eligible now
#     keeps it from ever being re-selected.
#   - SafetyDailyState/SafetyCheckIn data is never touched by any of this —
#     a Telegram outcome can only affect whether a SafetyAlert/
#     SafetyEmergency row is marked delivered, nothing else.
#
# Concurrency correction: collect_due_*() itself never just reads eligible
# rows — for each one it also wins an atomic short-lived delivery lease
# (SafetyAlert.delivery_claimed_at / SafetyEmergency.notification_claimed_at,
# see safety_notify.DELIVERY_LEASE_SECONDS) before returning it, so two
# independent/concurrent collectors can never both pick the same row for
# delivery. This loop always releases a lease it doesn't use: on a False
# send it releases immediately (_release_alert_claim_sync /
# _release_sos_claim_sync) so the very next tick can retry without waiting
# out the lease; on a genuine crash mid-delivery the lease is simply left
# to expire on its own.
#
# Each due item's send+mark is handled in its own try/except so one failing
# notification (a raised exception, not just a False return — see
# safety_telegram._send, which already never raises under normal failure)
# can never prevent any other due reminder/missed-alert/SOS in the same
# batch from being attempted. The sync DB work (collecting, and the sync
# half of marking-notified) runs off the event loop via asyncio.to_thread
# (matching the S5 loop above); the httpx sends run directly on the event
# loop (already async/non-blocking).
# ---------------------------------------------------------------------------

_safety_notify_logger = logging.getLogger("safety_notify_loop")
_SAFETY_NOTIFY_INTERVAL_SECONDS = 30
_safety_notify_task: asyncio.Task | None = None

# ORM-handoff fix: SessionLocal (database.py) is intentionally left at its
# default expire_on_commit=True for the rest of the app — every other
# Session in this codebase is used and closed within a single function, so
# there's nothing to expire-and-then-read afterward. _collect_due_safety_
# notifications is different: collect_due_*() commits internally while
# claiming leases, and the ORM objects it returns (user, alert, daily_state,
# emergency) are read by safety_telegram's formatters *after* this session
# has already been closed. With expire_on_commit=True those objects are
# expired by each intervening commit, so any attribute access after close()
# raises DetachedInstanceError -- reproduced in production: the SafetyAlert
# got claimed correctly, but delivery never reached Telegram because
# formatting the message required reading user.display_name etc. off an
# expired instance. A local sessionmaker with expire_on_commit=False, scoped
# to just this one collection function, is the fix -- it changes nothing
# about how the rest of the app's Sessions behave.
_SafetyNotifySession = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


def _collect_due_safety_notifications():
    """Sync DB work for one notify tick — run via asyncio.to_thread so it
    never blocks the FastAPI event loop. The missed-alert last-known-check-in
    lookup reuses the same open session before it's closed. Nothing here is
    marked delivered — that only happens after a confirmed-successful send,
    below. Each collector's claim_at (the exact lease value this tick just
    won) rides along with every due item so it can be threaded through to
    the matching mark_*/release_* call and prove lease ownership there.

    Uses _SafetyNotifySession (expire_on_commit=False), not the app-wide
    SessionLocal, because the ORM objects returned here are read by
    safety_telegram's message formatters after this session is closed --
    see the comment on _SafetyNotifySession above."""
    db = _SafetyNotifySession()
    try:
        now = datetime.now(timezone.utc)
        reminders = collect_due_early_reminders(db, now)
        missed_raw = collect_due_missed_alerts(db, now)
        missed = [
            (user, daily_state, alert, claim_at, last_checkin_before(db, user.id, daily_state.deadline_utc))
            for user, daily_state, alert, claim_at in missed_raw
        ]
        late_checkins = collect_due_late_checkin_alerts(db, now)
        sos = collect_due_sos_notifications(db, now)
        return reminders, missed, late_checkins, sos
    finally:
        db.close()


def _mark_alert_notified_sync(alert_id: int, claim_at: datetime) -> None:
    db = SessionLocal()
    try:
        mark_alert_notified(db, alert_id, datetime.now(timezone.utc), claim_at)
    finally:
        db.close()


def _mark_sos_notified_sync(emergency_id: int, claim_at: datetime) -> None:
    db = SessionLocal()
    try:
        mark_sos_notified(db, emergency_id, datetime.now(timezone.utc), claim_at)
    finally:
        db.close()


def _release_alert_claim_sync(alert_id: int, claim_at: datetime) -> None:
    db = SessionLocal()
    try:
        release_alert_delivery_claim(db, alert_id, claim_at)
    finally:
        db.close()


def _release_sos_claim_sync(emergency_id: int, claim_at: datetime) -> None:
    db = SessionLocal()
    try:
        release_sos_delivery_claim(db, emergency_id, claim_at)
    finally:
        db.close()


def _mark_late_checkin_notified_sync(alert_id: int, claim_at: datetime) -> None:
    db = SessionLocal()
    try:
        mark_late_checkin_notified(db, alert_id, datetime.now(timezone.utc), claim_at)
    finally:
        db.close()


def _release_late_checkin_claim_sync(alert_id: int, claim_at: datetime) -> None:
    db = SessionLocal()
    try:
        release_late_checkin_delivery_claim(db, alert_id, claim_at)
    finally:
        db.close()


async def _deliver_early_reminder(user, alert, claim_at) -> None:
    try:
        sent = await safety_telegram.send_early_reminder(user)
        if sent:
            await asyncio.to_thread(_mark_alert_notified_sync, alert.id, claim_at)
        else:
            # Release the lease immediately so the very next tick can
            # retry, rather than waiting out DELIVERY_LEASE_SECONDS. Passes
            # the exact claim_at this call won -- if that lease was already
            # reclaimed by a newer worker (this one having stalled past
            # DELIVERY_LEASE_SECONDS), this becomes a safe no-op instead of
            # wiping out the new owner's lease.
            await asyncio.to_thread(_release_alert_claim_sync, alert.id, claim_at)
    except Exception:
        _safety_notify_logger.exception(
            "early reminder delivery failed for user_id=%s alert_id=%s — "
            "lease will expire and retry",
            user.id, alert.id,
        )


async def _deliver_missed_alert(user, daily_state, alert, claim_at, last_checkin) -> None:
    try:
        sent = await safety_telegram.send_missed_checkin_alert(user, daily_state, last_checkin)
        if sent:
            await asyncio.to_thread(_mark_alert_notified_sync, alert.id, claim_at)
        else:
            await asyncio.to_thread(_release_alert_claim_sync, alert.id, claim_at)
    except Exception:
        _safety_notify_logger.exception(
            "missed-checkin alert delivery failed for user_id=%s alert_id=%s — "
            "lease will expire and retry",
            user.id, alert.id,
        )


async def _deliver_late_checkin_alert(user, checkin, alert, claim_at) -> None:
    try:
        sent = await safety_telegram.send_late_checkin_alert(user, checkin, alert)
        if sent:
            await asyncio.to_thread(_mark_late_checkin_notified_sync, alert.id, claim_at)
        else:
            await asyncio.to_thread(_release_late_checkin_claim_sync, alert.id, claim_at)
    except Exception:
        _safety_notify_logger.exception(
            "late-checkin alert delivery failed for user_id=%s alert_id=%s — "
            "lease will expire and retry",
            user.id, alert.id,
        )


async def _deliver_sos_notification(user, emergency, claim_at) -> None:
    try:
        sent = await safety_telegram.send_sos_notification(user, emergency)
        if sent:
            await asyncio.to_thread(_mark_sos_notified_sync, emergency.id, claim_at)
        else:
            await asyncio.to_thread(_release_sos_claim_sync, emergency.id, claim_at)
    except Exception:
        _safety_notify_logger.exception(
            "SOS delivery failed for user_id=%s emergency_id=%s — "
            "lease will expire and retry",
            user.id, emergency.id,
        )


async def _safety_notify_eval_loop() -> None:
    try:
        while True:
            try:
                reminders, missed, late_checkins, sos = await asyncio.to_thread(
                    _collect_due_safety_notifications
                )
            except Exception:
                _safety_notify_logger.exception("safety notify loop collection tick failed")
                reminders, missed, late_checkins, sos = [], [], [], []

            # Each item's delivery is independently try/excepted inside the
            # _deliver_* helpers above, so one failure here can never skip
            # or abort any later item in this same batch — including a due
            # SOS after a failed early reminder. SOS is dispatched first,
            # then missed check-ins, then late-checkin notices, then early
            # reminders -- the most urgent notification in a batch should
            # never sit behind less urgent ones.
            for user, emergency, claim_at in sos:
                await _deliver_sos_notification(user, emergency, claim_at)
            for user, daily_state, alert, claim_at, last_checkin in missed:
                await _deliver_missed_alert(user, daily_state, alert, claim_at, last_checkin)
            for user, checkin, alert, claim_at in late_checkins:
                await _deliver_late_checkin_alert(user, checkin, alert, claim_at)
            for user, alert, claim_at in reminders:
                await _deliver_early_reminder(user, alert, claim_at)

            await asyncio.sleep(_SAFETY_NOTIFY_INTERVAL_SECONDS)
    except asyncio.CancelledError:
        raise


@app.on_event("startup")
async def _start_safety_notify_eval_loop() -> None:
    global _safety_notify_task
    _safety_notify_task = asyncio.create_task(_safety_notify_eval_loop())


@app.on_event("shutdown")
async def _stop_safety_notify_eval_loop() -> None:
    if _safety_notify_task is None:
        return
    _safety_notify_task.cancel()
    try:
        await _safety_notify_task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# SHADZ Admin Core
#
# All routes under /admin/* live here.
# Single dependency (verify_admin) applied at router level — no per-route
# repetition needed. Adding a new admin route automatically inherits auth.
#
# Current module: Redirect Engine
# Future modules: Analytics, NFC Client Manager, Settings, AI tools, etc.
#
# Planned route expansion (do not add yet):
#   /admin/redirect/...   — Redirect Engine management
#   /admin/analytics/...  — Scan charts and reporting
#   /admin/clients/...    — NFC client management
#   /admin/settings/...   — System configuration
# ---------------------------------------------------------------------------

admin_router = APIRouter(
    prefix="/admin",
    tags=["SHADZ Admin"],
    dependencies=[Depends(verify_admin)],
)


@admin_router.get("", include_in_schema=False)
def admin_ui():
    """Serves the SHADZ Admin Dashboard.
    HTTP Basic Auth triggers the browser's native login popup on first visit.
    Once authenticated, all subsequent /admin/* fetch calls are authorised
    automatically via the browser's cached credentials.
    """
    return FileResponse("static/admin.html")


# Legacy NFC admin route lives in nfc_legacy.py — registered here.
register_nfc_admin_routes(admin_router)

# Link Engine admin routes live in link_admin.py — registered here.
register_link_admin_routes(admin_router)

# Media Engine admin routes live in media_admin.py — registered here.
register_media_admin_routes(admin_router)

# Page Engine v1 admin routes live in page_admin.py — registered here.
register_page_admin_routes(admin_router)

# Bot Engine admin routes live in bot_admin.py — registered here.
register_bot_admin_routes(admin_router)

# Safety Engine admin routes live in safety_admin.py — registered here.
register_safety_admin_routes(admin_router)

# Register admin_router BEFORE /{slug} — ensures /admin is never captured
# by the catch-all slug route below.
app.include_router(admin_router)


# ---------------------------------------------------------------------------
# Public NFC redirect — registered LAST
# /{slug} is a single-segment catch-all. Must come after all other routes.
# ---------------------------------------------------------------------------

@app.get("/{slug}")
def redirect_slug(slug: str, request: Request, db: Session = Depends(get_db)):
    """Public endpoint — NFC tags point here (e.g. shadz.io/a).

    For url/media slugs, this is also the Activation Engine v1 Activation
    Gateway: an unactivated slug's first scan is redirected into the
    Telegram activation entry flow instead of its normal behaviour below.

    Behaviour depends on the slug's content_type:
      url   → 302 redirect to destination_url  (legacy behaviour unchanged)
      media → render lightweight media page (or 'Media not ready yet' page)
      page  → renders active attached page via Page Engine (404 if none attached)
      other → 302 redirect to destination_url for backward-compat with old slugs
    """
    if slug in RESERVED_SLUGS:
        raise HTTPException(status_code=404, detail=f"'{slug}' is a reserved path")

    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")

    if link.is_archived is True:
        return expired_page_response()

    link.scan_count += 1
    link.updated_at = datetime.now(timezone.utc)
    db.commit()

    ct = link.content_type

    # ── Activation Engine v1 Phase A2 — first-scan Activation Gateway ───────
    if ct in ("url", "media"):
        activation_redirect = resolve_activation_redirect(slug, db)
        if activation_redirect is not None:
            return activation_redirect

    # ── media ──────────────────────────────────────────────────────────────
    if ct == "media":
        return serve_public_media(slug, db)

    # ── page ───────────────────────────────────────────────────────────────
    if ct == "page":
        return serve_public_page(slug, db)

    # ── url + legacy slugs → redirect ──────────────────────────────────────
    if not link.destination_url:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' has no destination URL")
    return RedirectResponse(url=link.destination_url, status_code=302)
