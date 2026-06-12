import os
import re
import time
import random
import string
import secrets
import platform
import subprocess
import psutil
import boto3
from botocore.config import Config as BotocoreConfig
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Depends, Security, Request, APIRouter, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse, HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader
from pydantic import BaseModel
from sqlalchemy import text, func, or_
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

import models
from database import Base, engine, get_db

Base.metadata.create_all(bind=engine)


def _run_migrations() -> None:
    """Safe lightweight migration for SQLite.

    Base.metadata.create_all never adds columns to an existing table, so we
    inspect PRAGMA table_info and ALTER TABLE ADD COLUMN for any column that
    is missing.  Running this multiple times is harmless — it skips columns
    that already exist.

    Only touches redirect_links.  No Alembic required.
    """
    new_cols = {
        "content_type": "VARCHAR",
        "client_name":  "VARCHAR",
        "phone_number": "VARCHAR",
        "notes":        "TEXT",
        "is_archived":  "BOOLEAN",
        "archived_at":  "DATETIME",
    }
    with engine.connect() as conn:
        rows = conn.execute(text("PRAGMA table_info(redirect_links)")).fetchall()
        existing = {row[1] for row in rows}   # row[1] = column name
        for col, col_type in new_cols.items():
            if col not in existing:
                conn.execute(text(
                    f"ALTER TABLE redirect_links ADD COLUMN {col} {col_type}"
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
# Media Engine v0.1 — R2 helpers
# ---------------------------------------------------------------------------

# Allowed media types and their accepted MIME types
ALLOWED_MEDIA_TYPES: dict[str, frozenset[str]] = {
    "video": frozenset({"video/mp4", "video/quicktime", "video/webm"}),
    "image": frozenset({"image/jpeg", "image/png", "image/webp"}),
    "audio": frozenset({"audio/mpeg", "audio/mp4", "audio/wav", "audio/x-wav", "audio/x-m4a"}),
    "gif":   frozenset({"image/gif"}),
}

# R2 client is initialised once on first use (lazy) so startup never fails if
# R2 env vars are absent (e.g. during local dev with no media uploads).
_r2_client = None


def _get_r2_client():
    global _r2_client
    if _r2_client is not None:
        return _r2_client
    account_id   = os.environ.get("R2_ACCOUNT_ID", "")
    access_key   = os.environ.get("R2_ACCESS_KEY_ID", "")
    secret_key   = os.environ.get("R2_SECRET_ACCESS_KEY", "")
    endpoint_url = os.environ.get(
        "R2_ENDPOINT_URL",
        f"https://{account_id}.r2.cloudflarestorage.com" if account_id else "",
    )
    if not all([account_id, access_key, secret_key, endpoint_url]):
        raise HTTPException(
            status_code=503,
            detail="R2 storage is not configured on this server",
        )
    _r2_client = boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=BotocoreConfig(signature_version="s3v4"),
        region_name="auto",
    )
    return _r2_client


def _make_storage_key(media_type: str, original_filename: str) -> str:
    """Return a deterministic, safe R2 object key for a new upload."""
    timestamp = int(time.time())
    # Keep only safe filename characters; preserve the extension
    safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', original_filename)
    return f"media/{media_type}/{timestamp}_{safe_name}"


def _make_public_url(storage_key: str) -> str:
    base = os.environ.get("R2_PUBLIC_BASE_URL", "").rstrip("/")
    return f"{base}/{storage_key}"


def _generate_presigned_put(storage_key: str, mime_type: str, expires: int = 300) -> str:
    """Generate an R2 presigned PUT URL valid for `expires` seconds."""
    client = _get_r2_client()
    bucket = os.environ.get("R2_BUCKET_NAME", "shadz-media")
    return client.generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": storage_key, "ContentType": mime_type},
        ExpiresIn=expires,
    )


# ---------------------------------------------------------------------------
# Media Engine v0.1 — public page templates
# ---------------------------------------------------------------------------

def _media_page_html(asset: models.MediaAsset) -> str:
    """Minimal dark media page rendered for GET /{media-slug}."""
    url = asset.public_url
    mt  = asset.media_type
    if mt == "video":
        media_block = (
            f'<video src="{url}" controls autoplay playsinline '
            f'style="max-width:100%;max-height:90vh;border-radius:6px"></video>'
        )
    elif mt in ("image", "gif"):
        media_block = (
            f'<img src="{url}" alt="media" '
            f'style="max-width:100%;max-height:90vh;object-fit:contain;border-radius:6px" />'
        )
    elif mt == "audio":
        media_block = (
            f'<div style="text-align:center;padding:2rem">'
            f'<p style="color:#7a5f28;font-size:.75rem;letter-spacing:.15em;'
            f'text-transform:uppercase;margin-bottom:1.5rem">Audio</p>'
            f'<audio src="{url}" controls autoplay '
            f'style="width:100%;max-width:480px"></audio></div>'
        )
    else:
        media_block = f'<a href="{url}" style="color:#c9a84c">Open Media</a>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#000;color:#d4d0c8;min-height:100vh;display:flex;
         align-items:center;justify-content:center;padding:1rem}}
    .wordmark{{position:fixed;top:1rem;left:50%;transform:translateX(-50%);
               font-family:system-ui,sans-serif;font-size:.65rem;
               letter-spacing:.25em;text-transform:uppercase;color:#2a2520}}
  </style>
</head>
<body>
  <div class="wordmark">SHADZ</div>
  {media_block}
</body>
</html>"""


def _media_not_ready_html(slug: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#000;color:#4a4540;min-height:100vh;display:flex;
         align-items:center;justify-content:center;font-family:system-ui,sans-serif}}
    p{{font-size:.75rem;letter-spacing:.2em;text-transform:uppercase}}
  </style>
</head>
<body><p>Media not ready yet</p></body>
</html>"""


def _page_placeholder_html(slug: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#000;color:#4a4540;min-height:100vh;display:flex;
         align-items:center;justify-content:center;font-family:system-ui,sans-serif}}
    p{{font-size:.75rem;letter-spacing:.2em;text-transform:uppercase}}
  </style>
</head>
<body><p>Coming soon</p></body>
</html>"""


def _expired_page_html() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SHADZ</title>
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    body{background:#000;color:#4a4540;min-height:100vh;display:flex;
         align-items:center;justify-content:center;font-family:system-ui,sans-serif;
         flex-direction:column;gap:1.5rem;padding:2rem;text-align:center}
    p{font-size:.75rem;letter-spacing:.2em;text-transform:uppercase;line-height:1.8}
    a{display:inline-block;margin-top:.5rem;padding:.55rem 1.4rem;
      border:1px solid #2a2520;border-radius:5px;
      font-size:.65rem;letter-spacing:.15em;text-transform:uppercase;
      color:#4a4540;text-decoration:none;transition:border-color .15s,color .15s}
    a:hover{border-color:#7a5f28;color:#c9a84c}
  </style>
</head>
<body>
  <p>SHADZ EXPERIENCE HAS EXPIRED.<br>CONTACT US TO REACTIVATE.</p>
  <a href="https://t.me/xshadzx" target="_blank" rel="noopener noreferrer">Contact</a>
</body>
</html>"""


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


# ── Media Engine schemas ─────────────────────────────────────────────────────

class UploadUrlRequest(BaseModel):
    """Request a presigned PUT URL for a new R2 upload."""
    filename:   str
    media_type: str   # video/image/audio/gif
    mime_type:  str
    file_size:  int   # bytes


class UploadUrlResponse(BaseModel):
    upload_url:  str
    storage_key: str
    public_url:  str


class MediaCompleteRequest(BaseModel):
    """Confirm a completed upload and persist the MediaAsset row."""
    media_type:        str
    storage_key:       str
    public_url:        str
    original_filename: str
    mime_type:         str
    file_size:         int


class MediaCompleteResponse(BaseModel):
    media_asset_id: int
    public_url:     str


class MediaAttachRequest(BaseModel):
    slug:           str
    media_asset_id: int


class MediaAssetOut(BaseModel):
    id:                int
    media_type:        str
    storage_provider:  str
    storage_key:       str
    public_url:        str
    original_filename: str
    mime_type:         str
    file_size:         int
    is_deleted:        bool
    created_at:        datetime
    deleted_at:        datetime | None
    usage_count:       int = 0

    model_config = {"from_attributes": True}


class SlugMediaOut(BaseModel):
    id:                int
    slug:              str
    media_asset_id:    int
    is_active:         bool
    created_at:        datetime
    public_url:        str
    original_filename: str
    media_type:        str


class MediaDetachRequest(BaseModel):
    """Body for POST /admin/media/detach — unlink active media from a slug."""
    slug: str


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
        if payload.phone_number is None:
            raise HTTPException(status_code=400, detail="Phone number is required")
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


# ── Media Engine — admin routes ─────────────────────────────────────────────
# (detach is added here; remaining media routes follow further below)

@admin_router.post("/media/detach")
def detach_media(payload: MediaDetachRequest, db: Session = Depends(get_db)):
    """Deactivate the active media attachment for a slug.

    - Does NOT delete the MediaAsset row.
    - Does NOT remove the file from R2.
    - Only sets SlugMedia.is_active = False for the current active record.
    - After detach the public slug shows 'Media not ready yet' until a new
      asset is attached via POST /admin/media/attach.
    """
    link = db.query(models.RedirectLink).filter(
        models.RedirectLink.slug == payload.slug
    ).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{payload.slug}' not found")

    sm = (db.query(models.SlugMedia)
            .filter(models.SlugMedia.slug == payload.slug,
                    models.SlugMedia.is_active == True)
            .first())
    if not sm:
        raise HTTPException(
            status_code=400,
            detail="No active media attached to this slug.",
        )

    detached_asset_id = sm.media_asset_id
    sm.is_active = False
    db.commit()
    return {
        "success": True,
        "slug": payload.slug,
        "detached_media_asset_id": detached_asset_id,
    }


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


@admin_router.post("/media/upload-url", response_model=UploadUrlResponse)
def get_upload_url(payload: UploadUrlRequest):
    """Step 1 of 2-step upload.

    Validates media_type + mime_type, generates a safe storage key, and returns
    a short-lived (300 s) presigned PUT URL so the browser can upload directly
    to R2 without routing the file bytes through the VPS.
    """
    allowed = ALLOWED_MEDIA_TYPES.get(payload.media_type)
    if allowed is None:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid media_type '{payload.media_type}'. "
                   f"Must be one of: {', '.join(sorted(ALLOWED_MEDIA_TYPES))}",
        )
    if payload.mime_type not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"mime_type '{payload.mime_type}' is not allowed for "
                   f"media_type '{payload.media_type}'. "
                   f"Allowed: {', '.join(sorted(allowed))}",
        )
    storage_key = _make_storage_key(payload.media_type, payload.filename)
    public_url  = _make_public_url(storage_key)
    upload_url  = _generate_presigned_put(storage_key, payload.mime_type)
    return UploadUrlResponse(
        upload_url=upload_url,
        storage_key=storage_key,
        public_url=public_url,
    )


@admin_router.post("/media/complete", response_model=MediaCompleteResponse, status_code=201)
def complete_upload(payload: MediaCompleteRequest, db: Session = Depends(get_db)):
    """Step 2 of 2-step upload.

    Called by the browser after a successful PUT to R2.  Persists the MediaAsset
    row and returns the new media_asset_id.
    """
    allowed = ALLOWED_MEDIA_TYPES.get(payload.media_type)
    if allowed is None or payload.mime_type not in allowed:
        raise HTTPException(status_code=400, detail="Invalid media_type or mime_type")
    asset = models.MediaAsset(
        media_type=payload.media_type,
        storage_provider="r2",
        storage_key=payload.storage_key,
        public_url=payload.public_url,
        original_filename=payload.original_filename,
        mime_type=payload.mime_type,
        file_size=payload.file_size,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return MediaCompleteResponse(media_asset_id=asset.id, public_url=asset.public_url)


@admin_router.post("/media/attach")
def attach_media(payload: MediaAttachRequest, db: Session = Depends(get_db)):
    """Attach a MediaAsset to a slug.

    - Slug must exist in redirect_links with content_type = 'media'.
    - Deactivates any current active SlugMedia for this slug.
    - Creates a new active SlugMedia record.
    - The same asset can be attached to many slugs.
    """
    link = db.query(models.RedirectLink).filter(
        models.RedirectLink.slug == payload.slug
    ).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{payload.slug}' not found")
    if link.content_type != "media":
        raise HTTPException(
            status_code=400,
            detail=f"Slug '{payload.slug}' has content_type '{link.content_type}', "
                   f"not 'media'. Only media slugs can have a media asset attached.",
        )
    asset = db.query(models.MediaAsset).filter(
        models.MediaAsset.id == payload.media_asset_id
    ).first()
    if not asset:
        raise HTTPException(
            status_code=404,
            detail=f"MediaAsset {payload.media_asset_id} not found",
        )
    if asset.is_deleted:
        raise HTTPException(
            status_code=400,
            detail=f"MediaAsset {payload.media_asset_id} has been deleted",
        )
    # Deactivate previous active record for this slug
    (db.query(models.SlugMedia)
       .filter(models.SlugMedia.slug == payload.slug, models.SlugMedia.is_active == True)
       .update({"is_active": False}))
    # Create new active record
    sm = models.SlugMedia(
        slug=payload.slug,
        media_asset_id=payload.media_asset_id,
        is_active=True,
    )
    db.add(sm)
    db.commit()
    return {"success": True, "slug": payload.slug, "media_asset_id": payload.media_asset_id}


@admin_router.get("/media/assets", response_model=list[MediaAssetOut])
def list_media_assets(
    include_deleted: bool = Query(False, description="Include soft-deleted assets"),
    db: Session = Depends(get_db),
):
    """Return MediaAsset records with a usage_count (active slug attachments).

    By default only non-deleted assets are returned.
    Pass ?include_deleted=true to include soft-deleted records.
    """
    q = db.query(models.MediaAsset)
    if not include_deleted:
        q = q.filter(models.MediaAsset.is_deleted == False)
    assets = q.order_by(models.MediaAsset.created_at.desc()).all()
    results = []
    for asset in assets:
        usage_count = (db.query(func.count(models.SlugMedia.id))
                         .filter(models.SlugMedia.media_asset_id == asset.id,
                                 models.SlugMedia.is_active == True)
                         .scalar() or 0)
        out = MediaAssetOut(
            id=asset.id,
            media_type=asset.media_type,
            storage_provider=asset.storage_provider,
            storage_key=asset.storage_key,
            public_url=asset.public_url,
            original_filename=asset.original_filename,
            mime_type=asset.mime_type,
            file_size=asset.file_size,
            is_deleted=asset.is_deleted,
            created_at=asset.created_at,
            deleted_at=asset.deleted_at,
            usage_count=usage_count,
        )
        results.append(out)
    return results


@admin_router.get("/media/slug/{slug}", response_model=list[SlugMediaOut])
def get_slug_media_history(slug: str, db: Session = Depends(get_db)):
    """Return full media attachment history for a slug, newest first."""
    rows = (db.query(models.SlugMedia)
              .filter(models.SlugMedia.slug == slug)
              .order_by(models.SlugMedia.created_at.desc())
              .all())
    results = []
    for sm in rows:
        asset = db.query(models.MediaAsset).filter(
            models.MediaAsset.id == sm.media_asset_id
        ).first()
        results.append(SlugMediaOut(
            id=sm.id,
            slug=sm.slug,
            media_asset_id=sm.media_asset_id,
            is_active=sm.is_active,
            created_at=sm.created_at,
            public_url=asset.public_url if asset else "",
            original_filename=asset.original_filename if asset else "",
            media_type=asset.media_type if asset else "",
        ))
    return results


@admin_router.delete("/media/assets/{media_asset_id}")
def soft_delete_asset(media_asset_id: int, db: Session = Depends(get_db)):
    """Soft-delete a MediaAsset (marks is_deleted=True; does NOT remove from R2).

    Refused if the asset is still linked to any active slugs — callers must
    replace or detach all active SlugMedia records first.  This prevents one
    delete from silently breaking many NFC tags (e.g. 100 event keychains
    sharing the same video).
    """
    asset = db.query(models.MediaAsset).filter(models.MediaAsset.id == media_asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail=f"MediaAsset {media_asset_id} not found")
    if asset.is_deleted:
        raise HTTPException(status_code=400, detail=f"MediaAsset {media_asset_id} is already deleted")

    # Safety check: refuse if any slug is still actively using this asset
    active_usage = (
        db.query(func.count(models.SlugMedia.id))
          .filter(
              models.SlugMedia.media_asset_id == media_asset_id,
              models.SlugMedia.is_active == True,
          )
          .scalar() or 0
    )
    if active_usage > 0:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Media asset is still linked to {active_usage} active slug(s). "
                f"Replace or detach active slugs before deleting."
            ),
        )

    asset.is_deleted = True
    asset.deleted_at = datetime.now(timezone.utc)
    db.commit()
    return {"success": True, "media_asset_id": media_asset_id}


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
      page  → placeholder 'Coming soon' page
      other → 302 redirect to destination_url for backward-compat with old slugs
    """
    if slug in RESERVED_SLUGS:
        raise HTTPException(status_code=404, detail=f"'{slug}' is a reserved path")

    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")

    if link.is_archived is True:
        return HTMLResponse(
            content=_expired_page_html(),
            status_code=410,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma":        "no-cache",
                "Expires":       "0",
            },
        )

    link.scan_count += 1
    link.updated_at = datetime.now(timezone.utc)
    db.commit()

    ct = link.content_type

    # ── media ──────────────────────────────────────────────────────────────
    if ct == "media":
        sm = (db.query(models.SlugMedia)
                .filter(models.SlugMedia.slug == slug,
                        models.SlugMedia.is_active == True)
                .first())
        if not sm:
            return HTMLResponse(content=_media_not_ready_html(slug))
        asset = db.query(models.MediaAsset).filter(
            models.MediaAsset.id == sm.media_asset_id
        ).first()
        if not asset or asset.is_deleted:
            return HTMLResponse(content=_media_not_ready_html(slug))
        return HTMLResponse(content=_media_page_html(asset))

    # ── page (placeholder) ─────────────────────────────────────────────────
    if ct == "page":
        return HTMLResponse(content=_page_placeholder_html(slug))

    # ── url + legacy slugs → redirect ──────────────────────────────────────
    if not link.destination_url:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' has no destination URL")
    return RedirectResponse(url=link.destination_url, status_code=302)
