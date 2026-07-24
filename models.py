from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Integer, BigInteger, Text, Boolean, ForeignKey, CheckConstraint
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
    display_name: Mapped[str | None] = mapped_column(String, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Page Engine v1 ───────────────────────────────────────────────────────────

PAGE_TEMPLATE_TYPES = {"invitation", "brand_product", "child_safety"}
PAGE_STATUSES = {"draft", "ready", "archived"}


class Page(Base):
    """One row per authored page.

    content_json is unstructured for now; schema is defined per-template at
    render time.  Pages are never hard-deleted; use status='archived'.
    """
    __tablename__ = "pages"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    template_type: Mapped[str] = mapped_column(String, nullable=False)   # see PAGE_TEMPLATE_TYPES
    status: Mapped[str] = mapped_column(String, default="draft", nullable=False)  # see PAGE_STATUSES
    content_json: Mapped[str | None] = mapped_column(Text, nullable=True)
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
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PageSlugAttachment(Base):
    """Join between a Page and a redirect_links slug.

    One page may attach to many slugs.  One slug may have only one active
    attachment (enforced by partial unique index idx_page_slug_one_active,
    created in _run_migrations).  History rows (is_active=False) are kept.
    """
    __tablename__ = "page_slug_attachments"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    page_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("pages.id"), index=True, nullable=False
    )
    slug: Mapped[str] = mapped_column(
        String, ForeignKey("redirect_links.slug"), index=True, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
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


# ── Telegram Bot Self-Service — Phase T1 ────────────────────────────────────

class BotClient(Base):
    """One row per customer bot client.

    access_code is stored plain text (admin must be able to view it when a
    customer forgets their code).  telegram_user_id / telegram_username are
    nullable — populated later when the customer binds their Telegram account.
    """
    __tablename__ = "bot_clients"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    client_name: Mapped[str] = mapped_column(String, nullable=False)
    access_code: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    telegram_user_id: Mapped[str | None] = mapped_column(String, nullable=True)
    telegram_username: Mapped[str | None] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
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


class BotClientSlug(Base):
    """Join between a BotClient and a redirect_links slug.

    One bot client can manage many slugs.  A slug may only be assigned to one
    bot client at a time (enforced by UNIQUE on slug).  Only url and media
    slugs are in scope — page slugs are rejected at the application layer.
    Assignments are hard-deleted when removed; no history preserved.
    Deactivating a bot client does NOT cascade to delete these rows.
    """
    __tablename__ = "bot_client_slugs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    bot_client_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("bot_clients.id"), index=True, nullable=False
    )
    slug: Mapped[str] = mapped_column(
        String, ForeignKey("redirect_links.slug"), unique=True, index=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# ── Activation Engine v1 — Phase A1 (Activation Data Foundation) ───────────

ACTIVATION_STATUSES = {"unactivated", "activated"}


class ActivationRecord(Base):
    """One row per activation-enabled slug (url or media content_type only).

    content_type is never duplicated here — it always comes from the
    corresponding redirect_links row. This table only tracks activation
    lifecycle state (see ACTIVATION_STATUSES) and the eventual owning
    BotClient. Activation routing, token consumption, and admin/bot UI are
    out of scope for Phase A1 — this is a data foundation only.
    """
    __tablename__ = "activation_records"
    __table_args__ = (
        CheckConstraint(
            "activation_status IN ('unactivated', 'activated')",
            name="ck_activation_records_activation_status",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    slug: Mapped[str] = mapped_column(
        String, ForeignKey("redirect_links.slug"), unique=True, index=True, nullable=False
    )
    activation_status: Mapped[str] = mapped_column(String, default="unactivated", nullable=False)
    activation_token: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    owner_client_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("bot_clients.id"), nullable=True
    )
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


_ACTIVATION_ELIGIBLE_CONTENT_TYPES = {"url", "media"}


def create_activation_record_for_slug(db, slug: str, activation_token: str) -> "ActivationRecord":
    """Build and stage (add/flush, not commit) an ActivationRecord for a slug.

    Looks up the existing RedirectLink by exact slug and raises ValueError if
    it does not exist, or if its content_type is not "url" or "media" (in
    particular, "page" slugs are rejected). The created record always starts
    unactivated with no owner and no activation timestamp — activation itself
    is out of scope for Phase A1. Does not commit; the caller controls the
    transaction. Does not generate tokens, create a BotClient, or assign a
    BotClientSlug.
    """
    link = db.query(RedirectLink).filter(RedirectLink.slug == slug).first()
    if not link:
        raise ValueError(f"Slug '{slug}' does not exist")
    if link.content_type not in _ACTIVATION_ELIGIBLE_CONTENT_TYPES:
        raise ValueError(
            f"Slug '{slug}' has content_type '{link.content_type}', "
            f"which is not activation-eligible (only url/media are)"
        )

    record = ActivationRecord(slug=slug, activation_token=activation_token)
    db.add(record)
    db.flush()
    return record


def delete_activation_lifecycle_for_slug(db, slug: str) -> None:
    """Stage deletion of activation-related rows for a slug being hard-deleted.

    Queues deletion of the slug's ActivationRecord (if any) and its
    BotClientSlug assignment (if any) within the caller's existing
    transaction. Never deletes the BotClient itself, and never touches the
    redirect_links row — callers are responsible for the actual slug
    deletion. This function does not commit or rollback; both deletes are
    only synchronous ORM-session operations against the same uncommitted
    transaction, and are only made durable (or discarded together) by
    whatever commit/rollback the caller performs afterward — there is no
    point at which the caller can safely commit between the two calls
    without risking a partially-applied cleanup. No hard-delete path for
    redirect_links exists yet in this codebase (slugs are only archived);
    this helper is ready for whichever future path performs that deletion.
    """
    db.query(ActivationRecord).filter(ActivationRecord.slug == slug).delete()
    db.query(BotClientSlug).filter(BotClientSlug.slug == slug).delete()


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
