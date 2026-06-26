"""Page Engine v1 — admin schemas, helpers, and route registration.

Extracted from main.py in Phase 4B. Call register_page_admin_routes(admin_router)
in main.py to wire all Page Engine admin routes onto the existing admin_router.
Routes inherit the router's /admin prefix and verify_admin dependency unchanged.
"""
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import models
from database import get_db


# ── Page Engine v1 — schemas ─────────────────────────────────────────────────

class PageCreateRequest(BaseModel):
    title: str
    template_type: str
    status: str = "draft"
    content_json: str | None = None


class PageUpdateRequest(BaseModel):
    title: str | None = None
    template_type: str | None = None
    status: str | None = None
    content_json: str | None = None


class PageOut(BaseModel):
    id: int
    title: str
    template_type: str
    status: str
    content_json: str | None = None
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None = None

    model_config = {"from_attributes": True}


class PageAttachRequest(BaseModel):
    page_id: int
    slug: str


class PageDetachRequest(BaseModel):
    slug: str


# ── Page Engine v1 — safety helpers ──────────────────────────────────────────

def _get_page_or_404(page_id: int, db: Session) -> models.Page:
    page = db.query(models.Page).filter(models.Page.id == page_id).first()
    if not page:
        raise HTTPException(status_code=404, detail=f"Page {page_id} not found")
    return page


def _validate_page_template(template_type: str) -> None:
    if template_type not in models.PAGE_TEMPLATE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid template_type '{template_type}'. "
                f"Must be one of: {sorted(models.PAGE_TEMPLATE_TYPES)}"
            ),
        )


def _validate_page_status(status: str) -> None:
    if status not in models.PAGE_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid status '{status}'. "
                f"Must be one of: {sorted(models.PAGE_STATUSES)}"
            ),
        )


def _get_active_page_attachment(slug: str, db: Session) -> models.PageSlugAttachment | None:
    return (
        db.query(models.PageSlugAttachment)
        .filter(
            models.PageSlugAttachment.slug == slug,
            models.PageSlugAttachment.is_active == True,
        )
        .first()
    )


# ── Page Engine v1 — admin route registration ─────────────────────────────────

def register_page_admin_routes(admin_router) -> None:
    """Register all Page Engine admin routes onto admin_router.

    Called in main.py before app.include_router(admin_router).
    Routes inherit the router's prefix (/admin) and dependencies (verify_admin).

    Route registration order matters for POST /admin/pages/*:
      Fixed paths (/attach, /detach) must come BEFORE the parametric path
      (/{page_id}) so FastAPI does not try to coerce "attach"/"detach" as int.
    GET /admin/pages/{page_id}/edit has a different segment count and is safe.
    """

    @admin_router.get("/pages/new", include_in_schema=False)
    def admin_page_new_form():
        """Minimal test form — create a new page."""
        template_options = "".join(
            f'<option value="{t}">{t}</option>'
            for t in sorted(models.PAGE_TEMPLATE_TYPES)
        )
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>New Page — SHADZ Admin</title>
  <style>
    body{{background:#0d0d0d;color:#d4d0c8;font-family:system-ui,sans-serif;
         max-width:520px;margin:3rem auto;padding:1.5rem}}
    h2{{font-size:.8rem;letter-spacing:.2em;text-transform:uppercase;
        color:#7a5f28;margin-bottom:1.5rem}}
    label{{display:block;font-size:.7rem;letter-spacing:.1em;
           text-transform:uppercase;color:#888;margin:.9rem 0 .25rem}}
    input,select,textarea{{width:100%;box-sizing:border-box;
      background:#1a1a1a;border:1px solid #2a2520;
      color:#d4d0c8;padding:.5rem .7rem;border-radius:4px;
      font-family:inherit;font-size:.85rem}}
    textarea{{height:120px;resize:vertical}}
    button{{margin-top:1.2rem;padding:.55rem 1.4rem;
            border:1px solid #7a5f28;border-radius:5px;
            background:transparent;color:#c9a84c;
            font-size:.7rem;letter-spacing:.15em;
            text-transform:uppercase;cursor:pointer}}
    pre{{margin-top:1.2rem;padding:.8rem;background:#1a1a1a;
         border-radius:4px;font-size:.75rem;white-space:pre-wrap;
         word-break:break-all;color:#888}}
    a{{display:inline-block;margin-top:1rem;font-size:.7rem;
       color:#555;text-decoration:none;letter-spacing:.1em}}
  </style>
</head>
<body>
  <h2>New Page</h2>
  <form id="f">
    <label>Title</label>
    <input name="title" required>
    <label>Template</label>
    <select name="template_type">{template_options}</select>
    <label>Status</label>
    <select name="status">
      <option value="draft">draft</option>
      <option value="ready">ready</option>
    </select>
    <label>Content JSON <span style="color:#555">(optional)</span></label>
    <textarea name="content_json" placeholder='{{}}'></textarea>
    <button type="submit">Create Page</button>
  </form>
  <pre id="r"></pre>
  <a href="/admin">← Admin</a>
  <script>
    document.getElementById('f').onsubmit = async e => {{
      e.preventDefault();
      const fd = new FormData(e.target);
      const body = {{}};
      for (const [k, v] of fd) {{ if (v !== '') body[k] = v; }}
      const r = await fetch('/admin/pages', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(body)
      }});
      document.getElementById('r').textContent = JSON.stringify(await r.json(), null, 2);
    }};
  </script>
</body>
</html>"""
        return HTMLResponse(content=html)

    @admin_router.post("/pages", response_model=PageOut, status_code=201)
    def create_page(payload: PageCreateRequest, db: Session = Depends(get_db)):
        """Create a new page row in the pages table.

        Does not attach to any slug — use POST /admin/pages/attach for that.
        Default status is 'draft'. template_type and status are validated against
        PAGE_TEMPLATE_TYPES and PAGE_STATUSES respectively.
        """
        _validate_page_template(payload.template_type)
        _validate_page_status(payload.status)

        title = payload.title.strip()
        if not title:
            raise HTTPException(status_code=400, detail="title cannot be blank")

        page = models.Page(
            title=title,
            template_type=payload.template_type,
            status=payload.status,
            content_json=payload.content_json,
        )
        db.add(page)
        db.commit()
        db.refresh(page)
        return page

    @admin_router.post("/pages/attach")
    def attach_page(payload: PageAttachRequest, db: Session = Depends(get_db)):
        """Attach a page to a slug.

        - slug must exist in redirect_links with content_type='page'.
        - page_id must exist in pages.
        - Deactivates any existing active attachment for this slug first.
        - Historical records (is_active=False) are preserved.
        - Partial unique index idx_page_slug_one_active is the safety net for
          any concurrent race; IntegrityError is caught and surfaced clearly.
        """
        link = db.query(models.RedirectLink).filter(
            models.RedirectLink.slug == payload.slug
        ).first()
        if not link:
            raise HTTPException(status_code=404, detail=f"Slug '{payload.slug}' not found")
        if link.content_type != "page":
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Slug '{payload.slug}' has content_type '{link.content_type}', not 'page'. "
                    f"Only page slugs can have a page attached."
                ),
            )

        page = _get_page_or_404(payload.page_id, db)

        now = datetime.now(timezone.utc)
        (
            db.query(models.PageSlugAttachment)
            .filter(
                models.PageSlugAttachment.slug == payload.slug,
                models.PageSlugAttachment.is_active == True,
            )
            .update({"is_active": False, "updated_at": now})
        )

        attachment = models.PageSlugAttachment(
            page_id=page.id,
            slug=payload.slug,
            is_active=True,
        )
        db.add(attachment)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Slug '{payload.slug}' already has an active page attachment. "
                    f"This should not happen — check the database state."
                ),
            )
        return {
            "success": True,
            "page_id": page.id,
            "slug": payload.slug,
            "message": f"Page {page.id} attached to slug '{payload.slug}'",
        }

    @admin_router.post("/pages/detach")
    def detach_page(payload: PageDetachRequest, db: Session = Depends(get_db)):
        """Deactivate the active page attachment for a slug.

        Safe no-op if no active attachment exists — returns success with a message
        instead of an error. Does not delete records; history is preserved.
        """
        attachment = _get_active_page_attachment(payload.slug, db)
        if not attachment:
            return {
                "success": True,
                "slug": payload.slug,
                "message": "No active page attachment found — nothing to detach.",
            }

        detached_page_id = attachment.page_id
        attachment.is_active = False
        attachment.updated_at = datetime.now(timezone.utc)
        db.commit()
        return {
            "success": True,
            "slug": payload.slug,
            "detached_page_id": detached_page_id,
            "message": f"Page {detached_page_id} detached from slug '{payload.slug}'",
        }

    @admin_router.get("/pages/{page_id}/edit", include_in_schema=False)
    def admin_page_edit_form(page_id: int, db: Session = Depends(get_db)):
        """Minimal test form — edit an existing page."""
        page = _get_page_or_404(page_id, db)
        template_options = "".join(
            f'<option value="{t}"{" selected" if t == page.template_type else ""}>{t}</option>'
            for t in sorted(models.PAGE_TEMPLATE_TYPES)
        )
        status_options = "".join(
            f'<option value="{s}"{" selected" if s == page.status else ""}>{s}</option>'
            for s in sorted(models.PAGE_STATUSES)
        )
        content_escaped = (page.content_json or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        title_escaped = page.title.replace("&", "&amp;").replace('"', "&quot;")
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Edit Page {page_id} — SHADZ Admin</title>
  <style>
    body{{background:#0d0d0d;color:#d4d0c8;font-family:system-ui,sans-serif;
         max-width:520px;margin:3rem auto;padding:1.5rem}}
    h2{{font-size:.8rem;letter-spacing:.2em;text-transform:uppercase;
        color:#7a5f28;margin-bottom:1.5rem}}
    label{{display:block;font-size:.7rem;letter-spacing:.1em;
           text-transform:uppercase;color:#888;margin:.9rem 0 .25rem}}
    input,select,textarea{{width:100%;box-sizing:border-box;
      background:#1a1a1a;border:1px solid #2a2520;
      color:#d4d0c8;padding:.5rem .7rem;border-radius:4px;
      font-family:inherit;font-size:.85rem}}
    textarea{{height:120px;resize:vertical}}
    button{{margin-top:1.2rem;padding:.55rem 1.4rem;
            border:1px solid #7a5f28;border-radius:5px;
            background:transparent;color:#c9a84c;
            font-size:.7rem;letter-spacing:.15em;
            text-transform:uppercase;cursor:pointer}}
    pre{{margin-top:1.2rem;padding:.8rem;background:#1a1a1a;
         border-radius:4px;font-size:.75rem;white-space:pre-wrap;
         word-break:break-all;color:#888}}
    a{{display:inline-block;margin-top:1rem;font-size:.7rem;
       color:#555;text-decoration:none;letter-spacing:.1em}}
  </style>
</head>
<body>
  <h2>Edit Page {page_id}</h2>
  <form id="f">
    <label>Title</label>
    <input name="title" value="{title_escaped}">
    <label>Template</label>
    <select name="template_type">{template_options}</select>
    <label>Status</label>
    <select name="status">{status_options}</select>
    <label>Content JSON <span style="color:#555">(optional)</span></label>
    <textarea name="content_json">{content_escaped}</textarea>
    <button type="submit">Update Page</button>
  </form>
  <pre id="r"></pre>
  <a href="/admin">← Admin</a>
  <script>
    document.getElementById('f').onsubmit = async e => {{
      e.preventDefault();
      const fd = new FormData(e.target);
      const body = {{}};
      for (const [k, v] of fd) {{ body[k] = v; }}
      const r = await fetch('/admin/pages/{page_id}', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(body)
      }});
      document.getElementById('r').textContent = JSON.stringify(await r.json(), null, 2);
    }};
  </script>
</body>
</html>"""
        return HTMLResponse(content=html)

    @admin_router.post("/pages/{page_id}", response_model=PageOut)
    def update_page(page_id: int, payload: PageUpdateRequest, db: Session = Depends(get_db)):
        """Update an existing page.

        Only fields explicitly provided (non-None) are changed. Omitted fields are
        preserved. Does not create a new page — use POST /admin/pages for that.
        Always updates updated_at on any change.
        """
        page = _get_page_or_404(page_id, db)

        if payload.template_type is not None:
            _validate_page_template(payload.template_type)
            page.template_type = payload.template_type

        if payload.status is not None:
            _validate_page_status(payload.status)
            page.status = payload.status

        if payload.title is not None:
            title = payload.title.strip()
            if not title:
                raise HTTPException(status_code=400, detail="title cannot be blank")
            page.title = title

        if payload.content_json is not None:
            page.content_json = payload.content_json

        page.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(page)
        return page
