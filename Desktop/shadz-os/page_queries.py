from sqlalchemy.orm import Session

import models


def get_active_page_attachment(slug: str, db: Session) -> models.PageSlugAttachment | None:
    return (
        db.query(models.PageSlugAttachment)
        .filter(
            models.PageSlugAttachment.slug == slug,
            models.PageSlugAttachment.is_active == True,
        )
        .first()
    )
