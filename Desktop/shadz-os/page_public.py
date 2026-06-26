from fastapi import HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

import models
from page_queries import get_active_page_attachment
from page_renderer import _render_page_html


def serve_public_page(slug: str, db: Session) -> HTMLResponse:
    attachment = get_active_page_attachment(slug, db)
    if not attachment:
        raise HTTPException(status_code=404, detail=f"No active page for '{slug}'")
    page = db.query(models.Page).filter(models.Page.id == attachment.page_id).first()
    if not page:
        raise HTTPException(status_code=404, detail=f"Page not found for '{slug}'")
    return HTMLResponse(content=_render_page_html(page))
