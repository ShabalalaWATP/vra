import uuid

from sqlalchemy import Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class SecretCandidate(Base):
    __tablename__ = "secret_candidates"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), index=True)
    file_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("files.id"))
    type: Mapped[str] = mapped_column(String(50))
    value_preview: Mapped[str | None] = mapped_column(String(20))
    line_number: Mapped[int | None] = mapped_column(Integer)
    confidence: Mapped[float | None] = mapped_column(Float)
    context: Mapped[str | None] = mapped_column(Text)
    is_false_positive: Mapped[bool] = mapped_column(default=False)
