from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Integer, BigInteger, Text, Boolean, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from database import Base


# ── Existing NFC system (unchanged) ─────────────────────────────────────────

class NFCRecord(Base):
    __tablename__ = "nfc_records"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    tag_id: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    target_url: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    tag_id: Mapped[str] = mapped_column(String, index=True, nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    user_agent: Mapped[str] = mapped_column(String, nullable=True)
    ip_address: Mapped[str] = mapped_column(String, nullable=True)


# ── v0.2 Dynamic Redirect System ────────────────────────────────────────────

class RedirectLink(Base):
    """One row per NFC slug (e.g. slug='a' → shadz.io/a).

    Client ownership fields (content_type, client_name, phone_number, notes)
    are nullable so that legacy records created before v0.3 are never broken.
    New records should always populate these fields.
    """
    __tablename__ = "redirect_links"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    slug: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    destination_url: Mapped[str] = mapped_column(String, nullable=False)
    scan_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # ── Client ownership / logging fields (added in v0.3) ──────────────────
    # All nullable — existing rows without these columns still load fine.
    content_type: Mapped[str | None] = mapped_column(String, nullable=True)
    client_name: Mapped[str | None] = mapped_column(String, nullable=True)
    phone_number: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Lifecycle fields (added in Phase 2) ───────────────────────────────────
    # Nullable so existing rows without these columns remain safe.
    # NULL must be treated as False (active) everywhere.
    is_archived: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Media Engine v0.1 ────────────────────────────────────────────────────────

class MediaAsset(Base):
    """One row per uploaded media file stored in R2.

    A single MediaAsset can be linked to many slugs (SlugMedia).  Assets are
    never auto-deleted from R2; soft-deletion marks the row is_deleted=True.
    """
    __tablename__ = "media_assets"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    media_type: Mapped[str] = mapped_column(String, nullable=False)       # video/image/audio/gif
    storage_provider: Mapped[str] = mapped_column(String, default="r2", nullable=False)
    storage_key: Mapped[str] = mapped_column(String, nullable=False)      # path inside bucket
    public_url: Mapped[str] = mapped_column(String, nullable=False)
    original_filename: Mapped[str] = mapped_column(String, nullable=False)
    mime_type: Mapped[str] = mapped_column(String, nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)    # bytes
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class SlugMedia(Base):
    """Join between a slug (RedirectLink) and a MediaAsset.

    History is preserved: replacing media creates a new active row and
    deactivates the old one.  Only one row per slug should have is_active=True.
    """
    __tablename__ = "slug_media"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    slug: Mapped[str] = mapped_column(String, index=True, nullable=False)
    media_asset_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("media_assets.id"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
