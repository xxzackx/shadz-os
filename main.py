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
from link_public import expired_page_response, serve_public_media
from nfc_legacy import register_nfc_routes, register_nfc_admin_routes
from bot_admin import register_bot_admin_routes

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

        # Normal indexes are declared via index=True on the model columns and
        # created by create_all.  Only the partial unique index is explicit here
        # because SQLAlchemy cannot express WHERE-clause indexes in mapped_column.
        # Partial unique index: only one active attachment per slug.
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_page_slug_one_active "
            "ON page_slug_attachments(slug) WHERE is_active = 1"
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
