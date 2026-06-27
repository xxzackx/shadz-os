import csv
import io
import os
import re
import time
import random
import string
import secrets
import platform
import subprocess
import psutil
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends, Security, Request, APIRouter, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse, StreamingResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader
from pydantic import BaseModel
from sqlalchemy import text, or_
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

import models
from database import Base, engine, get_db
from media_admin import register_media_admin_routes
from page_admin import register_page_admin_routes
from page_public import serve_public_page
from link_public import expired_page_response, serve_public_media

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

BOOT_TIME = psutil.boot_time()


# ---------------------------------------------------------------------------
# Auth — X-API-Key
# Used by legacy internal routes: /status, /run-command, /nfc/*
# ---------------------------------------------------------------------------

_API_KEY = os.environ.get("SHADZ_OS_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(key: str = Security(_api_key_header)) -> str:
    if not _API_KEY:
        raise HTTPException(status_code=500, detail="Server has no API key configured")
    if not key or key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")
    return key


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

_DF_CMD = (
    ["df", "-h"]
    if platform.system() == "Darwin"
    else ["df", "-h", "--output=source,size,used,avail,pcent,target"]
)

SAFE_COMMANDS: dict[str, list[str]] = {
    "check_docker": ["docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"],
    "check_disk":   _DF_CMD,
}

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
# Slug naming system
# Standard: {content_type}-{6 random lowercase alphanumeric chars}
# Examples: url-7h2k9x  media-a8d3f1  page-k9p2mx
# ---------------------------------------------------------------------------

VALID_CONTENT_TYPES: frozenset[str] = frozenset({"url", "media", "page"})

# Compiled once at startup for efficiency
SLUG_PATTERN = re.compile(r'^(url|media|page)-[a-z0-9]{6}$')

# Characters allowed in the random portion of a slug
_SLUG_CHARS = string.ascii_lowercase + string.digits  # a-z0-9


def is_valid_slug(slug: str) -> bool:
    """Return True if slug matches the SHADZ naming standard.
    Legacy slugs (e.g. 'a') return False — they can still be read/updated
    if they already exist in the database, but cannot be newly created.
    """
    return bool(SLUG_PATTERN.match(slug))


def infer_content_type_from_slug(slug: str) -> str | None:
    """Return the content_type prefix from a valid slug, or None for legacy slugs.
    Examples:  url-abc123 → 'url'   gift-a8d3f1 → 'gift'   'a' → None
    """
    return slug.split("-")[0] if is_valid_slug(slug) else None


def generate_slug(content_type: str, db: Session) -> str:
    """Auto-generate a unique slug for the given content_type.

    - content_type must be one of VALID_CONTENT_TYPES.
    - Retries up to 10 times to avoid collisions (extremely unlikely).
    - Raises 500 if all retries are exhausted.
    """
    if content_type not in VALID_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid content_type '{content_type}'. "
                   f"Must be one of: {sorted(VALID_CONTENT_TYPES)}",
        )
    for _ in range(10):
        random_id = ''.join(random.choices(_SLUG_CHARS, k=6))
        slug = f"{content_type}-{random_id}"
        exists = db.query(models.RedirectLink).filter(
            models.RedirectLink.slug == slug
        ).first()
        if not exists:
            return slug
    raise HTTPException(
        status_code=500,
        detail=f"Could not generate a unique slug for '{content_type}' "
               f"after 10 attempts — please try again",
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class CommandRequest(BaseModel):
    command: str


class CommandResult(BaseModel):
    command: str
    output: str
    exit_code: int


class ServerStatus(BaseModel):
    cpu_percent: float
    ram_percent: float
    ram_used_mb: float
    ram_total_mb: float
    uptime_seconds: float


class NFCCreate(BaseModel):
    tag_id: str
    target_url: str


class NFCUpdate(BaseModel):
    target_url: str


class NFCAdminUpdate(BaseModel):
    client_id: str
    new_target_url: str


class NFCStats(BaseModel):
    tag_id: str
    total_scans: int
    latest_scan_time: datetime | None


class NFCResponse(BaseModel):
    id: int
    tag_id: str
    target_url: str
    created_at: datetime

    model_config = {"from_attributes": True}


class LinkCreate(BaseModel):
    """Body for POST /admin/link — auto-generates slug from content_type.

    destination_url is required for url content_type.
    media and page slugs may omit it (stored as empty string).
    """
    content_type: str
    destination_url: str = ""   # optional for media/page; required for url
    client_name: str | None = None
    phone_number: str | None = None
    notes: str | None = None


class LinkUpdate(BaseModel):
    """Body for POST /admin/link/{slug} — upsert by slug.

    destination_url is optional so that callers can patch only the client-info
    fields (client_name, phone_number, notes) without touching the redirect URL.
    If destination_url is omitted the existing URL is preserved.
    Required when creating a new slug — the endpoint enforces this at runtime.
    """
    destination_url: str | None = None  # optional: keep existing value if omitted
    content_type: str | None = None     # optional override; inferred from slug if omitted
    client_name: str | None = None
    phone_number: str | None = None
    notes: str | None = None


class LinkInfo(BaseModel):
    """Full detail response for a single redirect link."""
    slug: str
    content_type: str | None = None
    client_name: str | None = None
    phone_number: str | None = None
    destination_url: str
    notes: str | None = None
    scan_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ActiveMediaInfo(BaseModel):
    """Active media attachment for a slug — embedded in search results."""
    media_asset_id:    int
    media_type:        str
    original_filename: str
    public_url:        str


class LinkSearchResult(BaseModel):
    """One item in the phone-number search response."""
    slug: str
    content_type: str | None = None
    client_name: str | None = None
    phone_number: str | None = None
    nfc_url: str               # computed: https://shadz.io/{slug}
    destination_url: str
    notes: str | None = None
    scan_count: int
    created_at: datetime
    updated_at: datetime
    active_media: ActiveMediaInfo | None = None   # populated for media slugs
    is_archived: bool = False


class SearchResponse(BaseModel):
    results: list[LinkSearchResult]


class BulkSlugRequest(BaseModel):
    """Body for POST /admin/links/bulk-archive and /admin/links/bulk-restore."""
    slugs: list[str]


class LinkConvertRequest(BaseModel):
    """Body for POST /admin/link/{slug}/convert — URL <-> Media type conversion.

    target_type must be "url" or "media".
    destination_url is required (and must be non-empty) when target_type == "url".
    """
    target_type: str
    destination_url: str | None = None


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


# ---------------------------------------------------------------------------
# Legacy internal routes — X-API-Key protected
# These predate the Admin Core and are used by internal tooling.
# ---------------------------------------------------------------------------

@app.get("/status", response_model=ServerStatus)
def get_status(_key=Depends(require_api_key)):
    mem = psutil.virtual_memory()
    return ServerStatus(
        cpu_percent=psutil.cpu_percent(interval=0.5),
        ram_percent=mem.percent,
        ram_used_mb=round(mem.used / 1024 / 1024, 1),
        ram_total_mb=round(mem.total / 1024 / 1024, 1),
        uptime_seconds=round(time.time() - BOOT_TIME, 1),
    )


@app.post("/run-command", response_model=CommandResult)
def run_command(req: CommandRequest, _key=Depends(require_api_key)):
    if req.command not in SAFE_COMMANDS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown command. Allowed: {list(SAFE_COMMANDS.keys())}",
        )
    argv = SAFE_COMMANDS[req.command]
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=10,
            # Never pass shell=True — argv is a fixed list, not user input
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Command timed out")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Binary not found: {argv[0]}")
    output = result.stdout or result.stderr
    return CommandResult(command=req.command, output=output.strip(), exit_code=result.returncode)


@app.post("/nfc", response_model=NFCResponse, status_code=201)
def create_nfc(payload: NFCCreate, db: Session = Depends(get_db), _key=Depends(require_api_key)):
    record = models.NFCRecord(tag_id=payload.tag_id, target_url=payload.target_url)
    db.add(record)
    try:
        db.commit()
        db.refresh(record)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"tag_id '{payload.tag_id}' already exists")
    return record


@app.get("/nfc/{tag_id}", response_model=NFCResponse)
def get_nfc(tag_id: str, db: Session = Depends(get_db), _key=Depends(require_api_key)):
    record = db.query(models.NFCRecord).filter(models.NFCRecord.tag_id == tag_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"tag_id '{tag_id}' not found")
    return record


@app.put("/nfc/{tag_id}", response_model=NFCResponse)
def update_nfc(tag_id: str, payload: NFCUpdate, db: Session = Depends(get_db), _key=Depends(require_api_key)):
    record = db.query(models.NFCRecord).filter(models.NFCRecord.tag_id == tag_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"tag_id '{tag_id}' not found")
    record.target_url = payload.target_url
    db.commit()
    db.refresh(record)
    return record


@app.get("/r/{tag_id}")
def redirect_nfc(tag_id: str, request: Request, db: Session = Depends(get_db)):
    record = db.query(models.NFCRecord).filter(models.NFCRecord.tag_id == tag_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"tag_id '{tag_id}' not found")
    log = models.ScanLog(
        tag_id=tag_id,
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )
    db.add(log)
    db.commit()
    return RedirectResponse(url=record.target_url, status_code=302)


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


# ── Redirect Engine — admin routes ─────────────────────────────────────────

@admin_router.post("/link", response_model=LinkInfo, status_code=201)
def create_link(payload: LinkCreate, db: Session = Depends(get_db)):
    """Create a new redirect link with an auto-generated slug.

    content_type must be one of: url, media, page
    destination_url is required for url; optional for media and page.
    """
    # generate_slug validates content_type and raises 400 if invalid
    slug = generate_slug(payload.content_type, db)

    # url links must have a destination
    if payload.content_type == "url" and not payload.destination_url:
        raise HTTPException(
            status_code=400,
            detail="destination_url is required for url content_type",
        )

    if payload.phone_number is None:
        raise HTTPException(status_code=400, detail="Phone number is required")
    phone = payload.phone_number.strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number cannot be blank")

    link = models.RedirectLink(
        slug=slug,
        destination_url=payload.destination_url,
        content_type=payload.content_type,
        client_name=payload.client_name,
        phone_number=phone,
        notes=payload.notes,
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link


@admin_router.get("/link/{slug}", response_model=LinkInfo)
def get_link(slug: str, db: Session = Depends(get_db)):
    """Return current destination URL and total scan count for a slug."""
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")
    return link


@admin_router.post("/link/{slug}", response_model=LinkInfo)
def upsert_link(slug: str, payload: LinkUpdate, db: Session = Depends(get_db)):
    """Update or create a redirect link by slug.

    - Slug EXISTS in DB → update any provided fields; omitted fields are left
      unchanged.  Legacy slugs (e.g. 'a') are allowed — no format check needed.
    - Slug NOT in DB + valid format → create new record; content_type inferred
      from slug prefix unless explicitly provided; destination_url required.
    - Slug NOT in DB + invalid format → 400.  Use POST /admin/link to auto-generate.

    content_type is validated against VALID_CONTENT_TYPES when provided.
    phone_number is free-form — no format validation.
    """
    # ── Validate content_type up-front (applies to both update and create paths) ──
    if payload.content_type is not None and payload.content_type not in VALID_CONTENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid content_type '{payload.content_type}'. "
                f"Must be one of: {', '.join(sorted(VALID_CONTENT_TYPES))}"
            ),
        )

    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()

    if link:
        # Update existing record — only touch fields that were explicitly provided
        if payload.destination_url is not None:
            link.destination_url = payload.destination_url
        if payload.content_type is not None:
            link.content_type = payload.content_type
        if payload.client_name is not None:
            link.client_name = payload.client_name
        if payload.phone_number is not None:
            phone = payload.phone_number.strip()
            if not phone:
                raise HTTPException(status_code=400, detail="Phone number cannot be blank")
            link.phone_number = phone
        if payload.notes is not None:
            link.notes = payload.notes
        link.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(link)
        return link

    # ── New slug: enforce naming standard ──────────────────────────────────────
    if not is_valid_slug(slug):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Slug '{slug}' does not exist and does not match the required format "
                f"(e.g. url-7h2k9x). Use POST /admin/link to auto-generate a slug."
            ),
        )

    # destination_url is required when creating a new slug
    if not payload.destination_url:
        raise HTTPException(
            status_code=400,
            detail="destination_url is required when creating a new slug",
        )

    if payload.phone_number is None:
        raise HTTPException(status_code=400, detail="Phone number is required")
    phone = payload.phone_number.strip()
    if not phone:
        raise HTTPException(status_code=400, detail="Phone number cannot be blank")

    # Infer content_type from slug prefix unless caller supplied one explicitly.
    # For any slug that passes is_valid_slug(), infer_content_type_from_slug()
    # always returns a non-None value — the guard below is a safety net.
    resolved_content_type = payload.content_type or infer_content_type_from_slug(slug)
    if resolved_content_type is None:
        raise HTTPException(
            status_code=400,
            detail="content_type could not be determined — please provide it explicitly",
        )

    link = models.RedirectLink(
        slug=slug,
        destination_url=payload.destination_url,
        content_type=resolved_content_type,
        client_name=payload.client_name,
        phone_number=phone,
        notes=payload.notes,
    )
    db.add(link)
    try:
        db.commit()
        db.refresh(link)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Slug '{slug}' already exists")
    return link


@admin_router.post("/link/{slug}/archive")
def archive_link(slug: str, db: Session = Depends(get_db)):
    """Soft-archive a redirect link.

    Sets is_archived=True and records archived_at timestamp.
    The public slug will return 410 and the expired page instead of redirecting.
    Idempotent: returns 200 without error if the slug is already archived.
    """
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")

    if link.is_archived is True:
        return {"success": True, "slug": slug, "is_archived": True, "message": "Already archived"}

    link.is_archived = True
    link.archived_at = datetime.now(timezone.utc)
    link.updated_at  = datetime.now(timezone.utc)
    db.commit()
    return {"success": True, "slug": slug, "is_archived": True, "message": "Link archived"}


@admin_router.post("/link/{slug}/restore")
def restore_link(slug: str, db: Session = Depends(get_db)):
    """Restore an archived redirect link to active.

    Clears is_archived and archived_at.
    NULL is treated as active — only explicit True is archived.
    Idempotent: returns 200 without error if the slug is already active.
    """
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")

    if link.is_archived is not True:
        return {"success": True, "slug": slug, "is_archived": False, "message": "Already active"}

    link.is_archived = False
    link.archived_at = None
    link.updated_at  = datetime.now(timezone.utc)
    db.commit()
    return {"success": True, "slug": slug, "is_archived": False, "message": "Link restored"}


@admin_router.post("/link/{slug}/convert")
def convert_link_type(slug: str, payload: LinkConvertRequest, db: Session = Depends(get_db)):
    """Convert a slug between url and media content types.

    Rules:
    - target_type must be "url" or "media" — "page" is rejected.
    - Slugs with null or "page" content_type are rejected.
    - url -> media: preserves destination_url; no media is auto-attached.
    - media -> url: requires destination_url; rejects if active media is attached.
    - archive status, scan_count, and client fields are never touched.
    """
    _CONVERTIBLE = frozenset({"url", "media"})

    if payload.target_type not in _CONVERTIBLE:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target_type '{payload.target_type}'. Must be 'url' or 'media'.",
        )

    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")

    if link.content_type is None:
        raise HTTPException(
            status_code=400,
            detail="Slug has no content_type set. Set it explicitly before converting.",
        )
    if link.content_type not in _CONVERTIBLE:
        raise HTTPException(
            status_code=400,
            detail=f"Slug content_type '{link.content_type}' cannot be converted in v0.1.",
        )

    # No-op: already the target type
    if link.content_type == payload.target_type:
        return {
            "success": True,
            "slug": link.slug,
            "content_type": link.content_type,
            "destination_url": link.destination_url,
            "message": f"Slug is already '{payload.target_type}' — no change.",
        }

    # ── media -> url ───────────────────────────────────────────────────────────
    if payload.target_type == "url":
        if not payload.destination_url or not payload.destination_url.strip():
            raise HTTPException(
                status_code=400,
                detail="destination_url is required when converting to url.",
            )
        active_sm = (
            db.query(models.SlugMedia)
              .filter(models.SlugMedia.slug == slug, models.SlugMedia.is_active == True)
              .first()
        )
        if active_sm:
            raise HTTPException(
                status_code=400,
                detail="Detach active media before converting this slug to URL.",
            )
        link.content_type = "url"
        link.destination_url = payload.destination_url.strip()
        link.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(link)
        return {
            "success": True,
            "slug": link.slug,
            "content_type": link.content_type,
            "destination_url": link.destination_url,
            "message": "Slug converted to url.",
        }

    # ── url -> media ───────────────────────────────────────────────────────────
    link.content_type = "media"
    link.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(link)
    return {
        "success": True,
        "slug": link.slug,
        "content_type": link.content_type,
        "destination_url": link.destination_url,
        "message": "Slug converted to media.",
    }


@admin_router.post("/links/bulk-archive")
def bulk_archive_links(payload: BulkSlugRequest, db: Session = Depends(get_db)):
    """Bulk soft-archive redirect links.

    Trims, drops empty strings, and de-duplicates slugs (preserving order).
    Returns {updated, skipped, errors, results} — never crashes on empty input.
    """
    seen: set[str] = set()
    clean: list[str] = []
    for s in payload.slugs:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            clean.append(s)

    if not clean:
        return {"updated": 0, "skipped": 0, "errors": [], "results": []}

    updated = 0
    skipped = 0
    results = []
    now = datetime.now(timezone.utc)

    for slug in clean:
        link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
        if not link:
            skipped += 1
            results.append({"slug": slug, "status": "not_found"})
            continue
        if link.is_archived is True:
            skipped += 1
            results.append({"slug": slug, "status": "already_archived"})
            continue
        link.is_archived = True
        link.archived_at = now
        link.updated_at  = now
        updated += 1
        results.append({"slug": slug, "status": "archived"})

    db.commit()
    return {"updated": updated, "skipped": skipped, "errors": [], "results": results}


@admin_router.post("/links/bulk-restore")
def bulk_restore_links(payload: BulkSlugRequest, db: Session = Depends(get_db)):
    """Bulk restore archived redirect links to active.

    Trims, drops empty strings, and de-duplicates slugs (preserving order).
    Returns {updated, skipped, errors, results} — never crashes on empty input.
    """
    seen: set[str] = set()
    clean: list[str] = []
    for s in payload.slugs:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            clean.append(s)

    if not clean:
        return {"updated": 0, "skipped": 0, "errors": [], "results": []}

    updated = 0
    skipped = 0
    results = []
    now = datetime.now(timezone.utc)

    for slug in clean:
        link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
        if not link:
            skipped += 1
            results.append({"slug": slug, "status": "not_found"})
            continue
        if link.is_archived is not True:
            skipped += 1
            results.append({"slug": slug, "status": "already_active"})
            continue
        link.is_archived = False
        link.archived_at = None
        link.updated_at  = now
        updated += 1
        results.append({"slug": slug, "status": "restored"})

    db.commit()
    return {"updated": updated, "skipped": skipped, "errors": [], "results": results}


@admin_router.get("/links/search", response_model=SearchResponse)
def search_links(
    phone_number: str = Query(..., description="Phone number to search (partial match)"),
    include_archived: bool = Query(False, description="Include archived slugs in results"),
    db: Session = Depends(get_db),
):
    """Search redirect links by phone number.
    Uses a partial LIKE match so '+855123' matches '+85512345678'.
    Returns all matching records sorted newest-first.
    Returns {"results": []} if nothing found — never 404.
    By default only active slugs are returned. Pass include_archived=true to include archived.
    NULL is_archived is treated as active (legacy rows).
    """
    q = (
        db.query(models.RedirectLink)
        .filter(models.RedirectLink.phone_number.like(f"%{phone_number}%"))
    )
    if not include_archived:
        q = q.filter(or_(
            models.RedirectLink.is_archived == False,
            models.RedirectLink.is_archived.is_(None),
        ))
    links = q.order_by(models.RedirectLink.created_at.desc()).all()
    results = []
    for link in links:
        # For media slugs, embed the active media attachment so the UI can
        # render the active-media panel and detach button without extra calls.
        active_media = None
        if link.content_type == "media":
            sm = (db.query(models.SlugMedia)
                    .filter(models.SlugMedia.slug == link.slug,
                            models.SlugMedia.is_active == True)
                    .first())
            if sm:
                asset = db.query(models.MediaAsset).filter(
                    models.MediaAsset.id == sm.media_asset_id,
                    models.MediaAsset.is_deleted == False,
                ).first()
                if asset:
                    active_media = ActiveMediaInfo(
                        media_asset_id=asset.id,
                        media_type=asset.media_type,
                        original_filename=asset.original_filename,
                        public_url=asset.public_url,
                    )
        results.append(LinkSearchResult(
            slug=link.slug,
            content_type=link.content_type,
            client_name=link.client_name,
            phone_number=link.phone_number,
            nfc_url=f"https://shadz.io/{link.slug}",
            destination_url=link.destination_url,
            notes=link.notes,
            scan_count=link.scan_count,
            created_at=link.created_at,
            updated_at=link.updated_at,
            active_media=active_media,
            is_archived=link.is_archived is True,
        ))
    return SearchResponse(results=results)


@admin_router.get("/links/export.csv")
def export_links_csv(
    include_archived: bool = Query(True, description="Include archived slugs (default: true — full export)"),
    q: str = Query(None, description="Optional search term — matches slug, phone_number, client_name, destination_url"),
    db: Session = Depends(get_db),
):
    """Export all link/client records as a UTF-8 CSV attachment.

    Default: all records including archived (include_archived=true).
    Optional q= filters by slug, phone_number, client_name, or destination_url (partial LIKE match).
    Protected by the same Basic Auth dependency as all /admin/* routes.
    """
    query = db.query(models.RedirectLink)

    if not include_archived:
        query = query.filter(or_(
            models.RedirectLink.is_archived == False,
            models.RedirectLink.is_archived.is_(None),
        ))

    if q:
        term = f"%{q}%"
        query = query.filter(or_(
            models.RedirectLink.slug.like(term),
            models.RedirectLink.phone_number.like(term),
            models.RedirectLink.client_name.like(term),
            models.RedirectLink.destination_url.like(term),
        ))

    links = query.order_by(models.RedirectLink.created_at.desc()).all()

    # Build a lookup: slug → active MediaAsset (if any)
    active_media_map: dict = {}
    media_slugs = [lnk.slug for lnk in links if lnk.content_type == "media"]
    if media_slugs:
        rows = (
            db.query(models.SlugMedia, models.MediaAsset)
            .join(models.MediaAsset, models.SlugMedia.media_asset_id == models.MediaAsset.id)
            .filter(
                models.SlugMedia.slug.in_(media_slugs),
                models.SlugMedia.is_active == True,
                models.MediaAsset.is_deleted == False,
            )
            .all()
        )
        for sm, asset in rows:
            active_media_map[sm.slug] = asset

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)

    writer.writerow([
        "slug",
        "content_type",
        "destination_url",
        "client_name",
        "phone_number",
        "is_archived",
        "archived_at",
        "scan_count",
        "created_at",
        "updated_at",
        "active_media_asset_id",
        "media_original_filename",
        "media_mime_type",
        "media_file_size_bytes",
        "media_storage_key",
    ])

    for link in links:
        asset = active_media_map.get(link.slug)
        writer.writerow([
            link.slug,
            link.content_type or "",
            link.destination_url,
            link.client_name or "",
            link.phone_number or "",
            "true" if link.is_archived is True else "false",
            link.archived_at.isoformat() if link.archived_at else "",
            link.scan_count,
            link.created_at.isoformat() if link.created_at else "",
            link.updated_at.isoformat() if link.updated_at else "",
            asset.id if asset else "",
            asset.original_filename if asset else "",
            asset.mime_type if asset else "",
            asset.file_size if asset else "",
            asset.storage_key if asset else "",
        ])

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"shadz_links_export_{timestamp}.csv"

    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Legacy NFC admin route (kept for backwards compatibility) ──────────────

@admin_router.patch("/nfc", response_model=NFCResponse)
def admin_update_nfc(payload: NFCAdminUpdate, db: Session = Depends(get_db)):
    """Legacy NFC admin update. Now protected by Admin Core (HTTP Basic Auth)
    instead of X-API-Key.
    """
    record = db.query(models.NFCRecord).filter(models.NFCRecord.tag_id == payload.client_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"client_id '{payload.client_id}' not found")
    record.target_url = payload.new_target_url
    db.commit()
    db.refresh(record)
    return record


# Media Engine admin routes live in media_admin.py — registered here.
register_media_admin_routes(admin_router)

# Page Engine v1 admin routes live in page_admin.py — registered here.
register_page_admin_routes(admin_router)

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
