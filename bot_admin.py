"""Bot Engine — admin schemas, helpers, and route registration (Phase T1).

Backend foundation for Telegram customer self-service.  Phase T1 adds DB tables
and admin CRUD only — no Telegram webhook, no bot token, no chat state machine.

Call register_bot_admin_routes(admin_router) in main.py to wire all Bot Engine
admin routes onto the existing admin_router.  Routes inherit the router's
/admin prefix and verify_admin dependency unchanged.
"""
import secrets
import string
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import models
from database import get_db


# ---------------------------------------------------------------------------
# Access code generation
# ---------------------------------------------------------------------------

# Uppercase letters + digits only (no lowercase). All chars including O and 0 are included.
_CODE_CHARS = string.ascii_uppercase + string.digits  # A-Z + 0-9


def _generate_access_code(db: Session) -> str:
    """Return a unique 6-char access code (A-Z + 0-9).

    Guarantees at least 1 letter and at least 1 digit per code.
    Retries on format failure or DB uniqueness collision up to 10 times.
    Raises 500 only if all retries are exhausted (extremely unlikely in practice).
    """
    for _ in range(10):
        code = "".join(secrets.choice(_CODE_CHARS) for _ in range(6))
        if not any(c.isdigit() for c in code):
            continue  # all letters — retry
        if not any(c.isalpha() for c in code):
            continue  # all digits — retry
        exists = (
            db.query(models.BotClient)
            .filter(models.BotClient.access_code == code)
            .first()
        )
        if not exists:
            return code
    raise HTTPException(
        status_code=500,
        detail="Could not generate a unique access code after 10 attempts — please try again",
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class BotClientCreateRequest(BaseModel):
    client_name: str


class BotClientUpdateRequest(BaseModel):
    client_name: str | None = None
    is_active: bool | None = None


class BotSlugAssignRequest(BaseModel):
    slug: str


class AssignedSlugOut(BaseModel):
    slug: str
    content_type: str | None = None
    notes: str | None = None
    is_archived: bool
    assigned_at: datetime

    model_config = {"from_attributes": True}


class BotClientOut(BaseModel):
    id: int
    client_name: str
    access_code: str
    telegram_user_id: str | None = None
    telegram_username: str | None = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    assigned_slugs: list[AssignedSlugOut] = Field(default_factory=list)

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_bot_client_or_404(client_id: int, db: Session) -> models.BotClient:
    client = (
        db.query(models.BotClient)
        .filter(models.BotClient.id == client_id)
        .first()
    )
    if not client:
        raise HTTPException(status_code=404, detail=f"Bot client {client_id} not found")
    return client


def _build_assigned_slugs(client_id: int, db: Session) -> list[AssignedSlugOut]:
    """Return assigned slug rows joined with redirect_links metadata."""
    rows = (
        db.query(models.BotClientSlug, models.RedirectLink)
        .join(models.RedirectLink, models.BotClientSlug.slug == models.RedirectLink.slug)
        .filter(models.BotClientSlug.bot_client_id == client_id)
        .all()
    )
    return [
        AssignedSlugOut(
            slug=bcs.slug,
            content_type=link.content_type,
            notes=link.notes,
            is_archived=link.is_archived is True,
            assigned_at=bcs.created_at,
        )
        for bcs, link in rows
    ]


def _client_out(client: models.BotClient, db: Session) -> BotClientOut:
    """Build a BotClientOut response including assigned slugs."""
    return BotClientOut(
        id=client.id,
        client_name=client.client_name,
        access_code=client.access_code,
        telegram_user_id=client.telegram_user_id,
        telegram_username=client.telegram_username,
        is_active=client.is_active,
        created_at=client.created_at,
        updated_at=client.updated_at,
        assigned_slugs=_build_assigned_slugs(client.id, db),
    )


# ---------------------------------------------------------------------------
# Route registration
# ---------------------------------------------------------------------------

def register_bot_admin_routes(admin_router) -> None:
    """Register all Bot Engine admin routes onto the shared admin_router.

    Called in main.py before app.include_router(admin_router).
    Routes inherit the router's prefix (/admin) and dependencies (verify_admin).
    """

    @admin_router.post("/bot/clients", response_model=BotClientOut, status_code=201)
    def create_bot_client(
        payload: BotClientCreateRequest, db: Session = Depends(get_db)
    ):
        """Create a new bot client with an auto-generated access code.

        access_code is returned in plain text so the admin can share it with
        the customer.  It is also visible later via GET /admin/bot/clients.
        """
        client_name = payload.client_name.strip()
        if not client_name:
            raise HTTPException(status_code=400, detail="client_name cannot be blank")

        code = _generate_access_code(db)

        client = models.BotClient(
            client_name=client_name,
            access_code=code,
            is_active=True,
        )
        db.add(client)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Failed to save bot client due to a conflict — please retry",
            )
        db.refresh(client)
        return _client_out(client, db)

    @admin_router.get("/bot/clients", response_model=list[BotClientOut])
    def list_bot_clients(db: Session = Depends(get_db)):
        """List all bot clients with their assigned slugs.

        Each assigned slug includes slug, content_type, notes, is_archived, and
        assigned_at — sufficient for admin visibility and future bot display
        (e.g. '1. (notes) — url slug').
        """
        clients = (
            db.query(models.BotClient)
            .order_by(models.BotClient.created_at.desc())
            .all()
        )
        return [_client_out(c, db) for c in clients]

    @admin_router.post("/bot/clients/{client_id}/slugs", status_code=201)
    def assign_slug(
        client_id: int,
        payload: BotSlugAssignRequest,
        db: Session = Depends(get_db),
    ):
        """Assign an existing url or media slug to a bot client.

        Rejects page slugs, archived slugs, and slugs already assigned to any
        bot client.  Only active bot clients may receive new assignments.
        """
        slug = payload.slug.strip()
        if not slug:
            raise HTTPException(status_code=400, detail="slug cannot be blank")

        client = _get_bot_client_or_404(client_id, db)
        if not client.is_active:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Bot client {client_id} is inactive. "
                    f"Reactivate the client before assigning slugs."
                ),
            )

        link = (
            db.query(models.RedirectLink)
            .filter(models.RedirectLink.slug == slug)
            .first()
        )
        if not link:
            raise HTTPException(status_code=404, detail=f"Slug '{slug}' not found")

        if link.content_type not in ("url", "media"):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Slug '{slug}' has content_type '{link.content_type}'. "
                    f"Only 'url' and 'media' slugs may be assigned to bot clients."
                ),
            )

        if link.is_archived is True:
            raise HTTPException(
                status_code=400,
                detail=f"Slug '{slug}' is archived and cannot be assigned",
            )

        assignment = models.BotClientSlug(bot_client_id=client_id, slug=slug)
        db.add(assignment)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=f"Slug '{slug}' is already assigned to a bot client",
            )

        return {
            "success": True,
            "bot_client_id": client_id,
            "slug": slug,
            "message": f"Slug '{slug}' assigned to bot client {client_id}",
        }

    @admin_router.delete("/bot/clients/{client_id}/slugs/{slug}")
    def remove_slug_assignment(
        client_id: int, slug: str, db: Session = Depends(get_db)
    ):
        """Remove a slug assignment from a bot client.

        Hard-deletes the assignment row only.  The redirect link itself is
        never touched.  Raises 404 if the assignment does not exist.
        """
        slug = slug.strip()
        if not slug:
            raise HTTPException(status_code=400, detail="slug cannot be blank")

        _get_bot_client_or_404(client_id, db)

        assignment = (
            db.query(models.BotClientSlug)
            .filter(
                models.BotClientSlug.bot_client_id == client_id,
                models.BotClientSlug.slug == slug,
            )
            .first()
        )
        if not assignment:
            raise HTTPException(
                status_code=404,
                detail=f"Slug '{slug}' is not assigned to bot client {client_id}",
            )

        db.delete(assignment)
        db.commit()
        return {
            "success": True,
            "bot_client_id": client_id,
            "slug": slug,
            "message": f"Slug '{slug}' removed from bot client {client_id}",
        }

    @admin_router.post("/bot/clients/{client_id}/regenerate-code")
    def regenerate_access_code(client_id: int, db: Session = Depends(get_db)):
        """Regenerate and save a new access code for a bot client.

        Returns the new code in plain text so the admin can share it.
        Old code is overwritten and cannot be recovered.
        """
        client = _get_bot_client_or_404(client_id, db)

        new_code = _generate_access_code(db)
        client.access_code = new_code
        client.updated_at = datetime.now(timezone.utc)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=500,
                detail="Failed to save new access code due to a conflict — please retry",
            )

        return {
            "success": True,
            "bot_client_id": client_id,
            "access_code": new_code,
            "message": f"Access code regenerated for bot client {client_id}",
        }

    @admin_router.patch("/bot/clients/{client_id}", response_model=BotClientOut)
    def update_bot_client(
        client_id: int,
        payload: BotClientUpdateRequest,
        db: Session = Depends(get_db),
    ):
        """Partially update a bot client's name or active status.

        Deactivating a client does NOT delete slug assignments — they are
        preserved so they can be restored when the client is reactivated.
        """
        client = _get_bot_client_or_404(client_id, db)

        if payload.client_name is not None:
            client_name = payload.client_name.strip()
            if not client_name:
                raise HTTPException(status_code=400, detail="client_name cannot be blank")
            client.client_name = client_name

        if payload.is_active is not None:
            client.is_active = payload.is_active

        client.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(client)
        return _client_out(client, db)
