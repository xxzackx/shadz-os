"""Link Engine — admin schemas, slug helpers, and route registration.

Extracted from main.py in Phase 4G. Call register_link_admin_routes(admin_router)
in main.py to wire all Link Engine admin routes onto the existing admin_router.
Routes inherit the router's /admin prefix and verify_admin dependency unchanged.
"""
import csv
import io
import re
import random
import secrets
import string
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import models
from database import get_db


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
# Activation Engine v1 Phase A2 — activation token generation
#
# Wires models.create_activation_record_for_slug (Phase A1) into the
# production slug-creation routes below: every newly-created url/media slug
# now gets an ActivationRecord so the public Activation Gateway
# (link_public.resolve_activation_redirect) can trigger. page slugs are
# never eligible — unchanged. Does not touch activation_status, ownership,
# or any other Activation Engine v1 phase's behaviour.
# ---------------------------------------------------------------------------

def _generate_activation_token(db: Session) -> str:
    """Auto-generate a unique, URL/Telegram-payload-safe activation token.

    secrets.token_urlsafe uses only the [A-Za-z0-9_-] charset that
    bot_runtime's Telegram deep-link/callback_data validator already
    requires, so a freshly-generated token never fails that check.
    Retries up to 10 times to avoid the (astronomically unlikely) event of
    a collision with an existing activation_token.
    """
    for _ in range(10):
        token = secrets.token_urlsafe(24)
        exists = db.query(models.ActivationRecord).filter(
            models.ActivationRecord.activation_token == token
        ).first()
        if not exists:
            return token
    raise HTTPException(
        status_code=500,
        detail="Could not generate a unique activation token after 10 attempts — please try again",
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class LinkCreate(BaseModel):
    """Body for POST /admin/link — auto-generates slug from content_type.

    destination_url is optional for all content types (Hotfix H1C) — stored
    as empty string if omitted, and may be populated later via Admin Change
    Destination or the Activation Engine.
    """
    content_type: str
    destination_url: str = ""   # optional for all content types
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


def _as_utc(value):
    """Tag a naive datetime as UTC before it reaches JSON serialization.

    RedirectLink timestamps are always written with datetime.now(timezone.utc),
    but SQLite/SQLAlchemy reads them back naive (a documented sqlite3
    limitation). A naive value serializes to JSON with no offset, which a
    browser `new Date(...)` call (as used throughout static/admin.html)
    silently misreads as local time instead of UTC — e.g. a slug created at
    2026-08-10 00:35 UTC+7 (2026-08-09T17:35:38 UTC) was displayed as
    2026-08-09 17:35 Cambodia time, 7 hours early (H1E). Already tz-aware
    values (e.g. a future non-SQLite backend) pass through unchanged, so
    this never double-converts.
    """
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


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

    _tag_utc = field_validator("created_at", "updated_at", mode="before")(_as_utc)


class ActiveMediaInfo(BaseModel):
    """Active media attachment for a slug — embedded in search results."""
    media_asset_id:    int
    media_type:        str
    original_filename: str
    public_url:        str


class ActivationInfo(BaseModel):
    """Activation Engine state for a slug — embedded in search results.

    Never includes the raw activation_token value — only has_activation_token
    (a presence boolean). Only populated for url/media slugs that have an
    ActivationRecord row; see search_links() for the legacy-slug distinction
    (missing record != unactivated — UI3D-B).
    """
    activation_status: str
    owner_client_id: int | None = None
    owner_client_name: str | None = None
    owner_telegram_username: str | None = None
    owner_client_active: bool | None = None
    activated_at: datetime | None = None
    has_activation_token: bool

    _tag_utc = field_validator("activated_at", mode="before")(_as_utc)


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
    # None means "no ActivationRecord" — for url/media this is a legacy slug
    # (predates the Activation Engine), not an unactivated one; for page
    # slugs it's simply out of scope. Never fabricated/backfilled here.
    activation: ActivationInfo | None = None

    _tag_utc = field_validator("created_at", "updated_at", mode="before")(_as_utc)


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
# Route registration
# ---------------------------------------------------------------------------

def register_link_admin_routes(admin_router):
    """Register all Link Engine admin routes onto the shared admin_router.

    Routes inherit the router's /admin prefix and verify_admin dependency.
    Call this in main.py before app.include_router(admin_router).
    """

    # ── Redirect Engine — admin routes ─────────────────────────────────────

    @admin_router.post("/link", response_model=LinkInfo, status_code=201)
    def create_link(payload: LinkCreate, db: Session = Depends(get_db)):
        """Create a new redirect link with an auto-generated slug.

        content_type must be one of: url, media, page
        destination_url is optional for all content types — a url slug may be
        created with no destination and populated later via Admin Change
        Destination or the Activation Engine (Hotfix H1C).
        """
        # generate_slug validates content_type and raises 400 if invalid
        slug = generate_slug(payload.content_type, db)

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
        try:
            db.flush()

            # Activation Engine v1 Phase A2: url/media slugs need an
            # ActivationRecord for the public Activation Gateway to trigger.
            if payload.content_type in ("url", "media"):
                token = _generate_activation_token(db)
                models.create_activation_record_for_slug(db, slug, token)

            db.commit()
            db.refresh(link)
        except Exception:
            # No exception is expected here in normal operation (the slug was
            # just uniquely generated, and content_type is already verified
            # activation-eligible) — but if one occurs, the RedirectLink and
            # any partially-staged ActivationRecord must never be left
            # half-committed. Roll back and re-raise unchanged; never swallow
            # or return a false success response.
            db.rollback()
            raise
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
          from slug prefix unless explicitly provided; destination_url is optional
          for url slugs (Hotfix H1C) but still required for media/page slugs
          (pre-H1C behaviour, unchanged).
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

        # destination_url is required for new media/page slugs (pre-H1C
        # behaviour, preserved); url slugs are exempt (Hotfix H1C).
        if resolved_content_type != "url" and not payload.destination_url:
            raise HTTPException(
                status_code=400,
                detail="destination_url is required when creating a new slug",
            )

        link = models.RedirectLink(
            slug=slug,
            destination_url=payload.destination_url or "",
            content_type=resolved_content_type,
            client_name=payload.client_name,
            phone_number=phone,
            notes=payload.notes,
        )
        db.add(link)
        try:
            db.flush()

            # Activation Engine v1 Phase A2: url/media slugs need an
            # ActivationRecord for the public Activation Gateway to trigger.
            if resolved_content_type in ("url", "media"):
                token = _generate_activation_token(db)
                models.create_activation_record_for_slug(db, slug, token)

            db.commit()
            db.refresh(link)
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"Slug '{slug}' already exists")
        except Exception:
            # Any other failure between the flush above and the commit —
            # e.g. ActivationRecord creation — must not leave the RedirectLink
            # half-committed. Roll back and re-raise unchanged.
            db.rollback()
            raise
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
        phone_number: str | None = Query(None, description="Phone number to search (partial match)"),
        slug: str | None = Query(None, description="Exact slug to look up"),
        include_archived: bool = Query(False, description="Include archived slugs in results"),
        db: Session = Depends(get_db),
    ):
        """Search redirect links by phone number, or look up one exact slug.
        Uses a partial LIKE match on phone_number so '+855123' matches '+85512345678'.
        slug, when provided, is an exact match — takes precedence over phone_number.
        Returns all matching records sorted newest-first.
        Returns {"results": []} if nothing found — never 404.
        By default only active slugs are returned. Pass include_archived=true to include archived.
        NULL is_archived is treated as active (legacy rows).
        Exactly one of phone_number or slug must be provided — 400 otherwise.
        """
        if not slug and not phone_number:
            raise HTTPException(
                status_code=400,
                detail="Either phone_number or slug is required",
            )

        q = db.query(models.RedirectLink)
        if slug:
            q = q.filter(models.RedirectLink.slug == slug)
        else:
            q = q.filter(models.RedirectLink.phone_number.like(f"%{phone_number}%"))
        if not include_archived:
            q = q.filter(or_(
                models.RedirectLink.is_archived == False,
                models.RedirectLink.is_archived.is_(None),
            ))
        links = q.order_by(models.RedirectLink.created_at.desc()).all()

        # ── Activation Engine v1 — UI3D-B batch read-only enrichment ────────
        # A missing ActivationRecord is NOT equivalent to "unactivated" — many
        # slugs were delivered to clients before the Activation Engine existed
        # and must never be treated as needing activation. This block only
        # SELECTs; it never creates/backfills an ActivationRecord for a slug
        # that doesn't have one.
        activation_eligible_slugs = [
            link.slug for link in links if link.content_type in ("url", "media")
        ]
        activation_by_slug: dict[str, models.ActivationRecord] = {}
        if activation_eligible_slugs:
            activation_records = (
                db.query(models.ActivationRecord)
                .filter(models.ActivationRecord.slug.in_(activation_eligible_slugs))
                .all()
            )
            activation_by_slug = {ar.slug: ar for ar in activation_records}

        owner_client_ids = {
            ar.owner_client_id
            for ar in activation_by_slug.values()
            if ar.owner_client_id is not None
        }
        owner_by_id: dict[int, models.BotClient] = {}
        if owner_client_ids:
            owners = (
                db.query(models.BotClient)
                .filter(models.BotClient.id.in_(owner_client_ids))
                .all()
            )
            owner_by_id = {owner.id: owner for owner in owners}

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

            activation = None
            ar = activation_by_slug.get(link.slug)
            if ar is not None:
                owner = owner_by_id.get(ar.owner_client_id) if ar.owner_client_id is not None else None
                activation = ActivationInfo(
                    activation_status=ar.activation_status,
                    owner_client_id=ar.owner_client_id,
                    owner_client_name=owner.client_name if owner else None,
                    owner_telegram_username=owner.telegram_username if owner else None,
                    owner_client_active=owner.is_active if owner else None,
                    activated_at=ar.activated_at,
                    has_activation_token=bool(ar.activation_token),
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
                activation=activation,
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
