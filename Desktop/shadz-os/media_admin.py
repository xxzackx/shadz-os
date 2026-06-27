"""Media Engine v0.1 — admin schemas, helpers, and route registration.

Extracted from main.py in Phase 4F. Call register_media_admin_routes(admin_router)
in main.py to wire all Media Engine admin routes onto the existing admin_router.
Routes inherit the router's /admin prefix and verify_admin dependency unchanged.
"""
import os
import re
import time

import boto3
from botocore.config import Config as BotocoreConfig
from datetime import datetime, timezone
from fastapi import Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

import models
from database import get_db


# ── Media Engine v0.1 — R2 helpers ──────────────────────────────────────────

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


# ── Media Engine schemas ──────────────────────────────────────────────────────

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
    display_name:      str | None = None   # optional human-readable label


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
    display_name:      str | None = None
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


class MediaAssetUpdateRequest(BaseModel):
    """Body for PATCH /admin/media/assets/{asset_id} — update display_name only."""
    display_name: str | None = None


class MediaDetachRequest(BaseModel):
    """Body for POST /admin/media/detach — unlink active media from a slug."""
    slug: str


# ── Media Engine — admin route registration ───────────────────────────────────

def register_media_admin_routes(admin_router) -> None:
    """Register all Media Engine admin routes onto admin_router.

    Called in main.py before app.include_router(admin_router).
    Routes inherit the router's prefix (/admin) and dependencies (verify_admin).
    """

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
        # Normalise display_name: blank/whitespace → None
        display_name = payload.display_name.strip() if payload.display_name else None
        display_name = display_name or None
        asset = models.MediaAsset(
            media_type=payload.media_type,
            storage_provider="r2",
            storage_key=payload.storage_key,
            public_url=payload.public_url,
            original_filename=payload.original_filename,
            mime_type=payload.mime_type,
            file_size=payload.file_size,
            display_name=display_name,
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
                display_name=asset.display_name,
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

    @admin_router.patch("/media/assets/{media_asset_id}")
    def update_asset_display_name(
        media_asset_id: int,
        payload: MediaAssetUpdateRequest,
        db: Session = Depends(get_db),
    ):
        """Update the display_name of a MediaAsset.

        Only display_name is writable — original_filename, public_url, storage_key,
        media_type, and file_size are never touched.
        Blank / whitespace-only display_name is stored as NULL (clears the name).
        Works on both active and soft-deleted assets.
        """
        asset = db.query(models.MediaAsset).filter(models.MediaAsset.id == media_asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail=f"MediaAsset {media_asset_id} not found")

        display_name = payload.display_name.strip() if payload.display_name else None
        display_name = display_name or None
        asset.display_name = display_name
        db.commit()
        return {
            "success": True,
            "id": asset.id,
            "display_name": asset.display_name,
            "original_filename": asset.original_filename,
        }

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
