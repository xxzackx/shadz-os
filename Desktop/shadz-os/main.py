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
from fastapi import FastAPI, HTTPException, Depends, Security, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

import models
from database import Base, engine, get_db

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Shadz OS", version="0.2.0")

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
# Examples: url-7h2k9x  gift-a8d3f1  video-k9p2mx
# ---------------------------------------------------------------------------

VALID_CONTENT_TYPES: frozenset[str] = frozenset({"url", "gift", "video", "audio", "page"})

# Compiled once at startup for efficiency
SLUG_PATTERN = re.compile(r'^(url|gift|video|audio|page)-[a-z0-9]{6}$')

# Characters allowed in the random portion of a slug
_SLUG_CHARS = string.ascii_lowercase + string.digits  # a-z0-9


def is_valid_slug(slug: str) -> bool:
    """Return True if slug matches the SHADZ naming standard.
    Legacy slugs (e.g. 'a') return False — they can still be read/updated
    if they already exist in the database, but cannot be newly created.
    """
    return bool(SLUG_PATTERN.match(slug))


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
    """Body for POST /admin/link — auto-generates slug from content_type."""
    content_type: str      # must be one of VALID_CONTENT_TYPES
    destination_url: str


class LinkUpdate(BaseModel):
    """Body for POST /admin/link/{slug} — updates destination of existing slug."""
    destination_url: str


class LinkInfo(BaseModel):
    slug: str
    destination_url: str
    scan_count: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """Public health check — no auth required."""
    return {"status": "ok"}


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
    Body: {"content_type": "url", "destination_url": "https://example.com"}
    content_type must be one of: url, gift, video, audio, page
    Returns the created record including the generated slug.
    """
    # generate_slug validates content_type and raises 400 if invalid
    slug = generate_slug(payload.content_type, db)
    link = models.RedirectLink(slug=slug, destination_url=payload.destination_url)
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

    - Slug EXISTS in DB → update destination_url (legacy slugs like 'a' allowed).
    - Slug NOT in DB + valid format → create new record.
    - Slug NOT in DB + invalid format → 400. Use POST /admin/link to auto-generate.

    Body: {"destination_url": "https://example.com"}
    """
    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()

    if link:
        # Update existing — legacy slugs (e.g. 'a') are allowed here
        link.destination_url = payload.destination_url
        link.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(link)
        return link

    # Slug does not exist — enforce naming standard for new creation
    if not is_valid_slug(slug):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Slug '{slug}' does not exist and does not match the required format "
                f"(e.g. url-7h2k9x). Use POST /admin/link to auto-generate a slug."
            ),
        )

    # Valid new slug — create it
    link = models.RedirectLink(slug=slug, destination_url=payload.destination_url)
    db.add(link)
    try:
        db.commit()
        db.refresh(link)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail=f"Slug '{slug}' already exists")
    return link


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
    Looks up the slug, increments scan_count, then issues a 302 redirect.
    Returns 404 if the slug is reserved or doesn't exist in the database.
    """
    # Guard: never process reserved paths as slugs.
    # FastAPI route order already prevents this, but this makes it explicit.
    if slug in RESERVED_SLUGS:
        raise HTTPException(status_code=404, detail=f"'{slug}' is a reserved path")

    link = db.query(models.RedirectLink).filter(models.RedirectLink.slug == slug).first()
    if not link:
        raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")

    link.scan_count += 1
    link.updated_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse(url=link.destination_url, status_code=302)
