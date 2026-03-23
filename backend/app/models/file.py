import uuid
from datetime import datetime, timezone

from sqlalchemy import Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class File(Base):
    __tablename__ = "files"
    __table_args__ = (UniqueConstraint("scan_id", "path"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), index=True)
    path: Mapped[str] = mapped_column(Text)
    language: Mapped[str | None] = mapped_column(String(50))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    line_count: Mapped[int | None] = mapped_column(Integer)
    priority_score: Mapped[float] = mapped_column(Float, default=0.0)
    score_reasons: Mapped[dict | None] = mapped_column(JSONB)
    is_test: Mapped[bool] = mapped_column(default=False)
    is_config: Mapped[bool] = mapped_column(default=False)
    is_generated: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    summaries: Mapped[list["FileSummary"]] = relationship(
        back_populates="file", lazy="selectin", cascade="all, delete-orphan"
    )
    symbols: Mapped[list["Symbol"]] = relationship(
        back_populates="file", lazy="selectin", cascade="all, delete-orphan"
    )
    scanner_results: Mapped[list["ScannerResult"]] = relationship(
        back_populates="file", lazy="select", cascade="all, delete-orphan"
    )


class FileSummary(Base):
    __tablename__ = "file_summaries"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("files.id"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    summary: Mapped[str] = mapped_column(Text)
    purpose: Mapped[str | None] = mapped_column(String(100))
    layer: Mapped[str | None] = mapped_column(String(50))
    security_notes: Mapped[str | None] = mapped_column(Text)
    generated_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    file: Mapped["File"] = relationship(back_populates="summaries")
