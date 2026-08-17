import os
import secrets
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import text
from sqlalchemy.orm import Session

import models
from database import Base, engine, get_db
from link_admin import register_link_admin_routes
from media_admin import register_media_admin_routes
from page_admin import register_page_admin_routes
from page_public import serve_public_page
from link_public import expired_page_response, resolve_activation_redirect, serve_public_media
from safety_public import serve_safety_entry
from nfc_legacy import register_nfc_routes, register_nfc_admin_routes
from bot_admin import register_bot_admin_routes
from bot_runtime import register_bot_webhook_routes

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
