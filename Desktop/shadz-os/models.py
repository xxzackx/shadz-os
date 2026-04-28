from datetime import datetime, timezone
from sqlalchemy import String, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from database import Base


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
