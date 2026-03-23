import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"))
    llm_profile_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("llm_profiles.id"))
    mode: Mapped[str] = mapped_column(String(20))  # light, regular, heavy
    status: Mapped[str] = mapped_column(String(20), default="pending")
    current_phase: Mapped[str | None] = mapped_column(String(50))
    current_task: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None]
    completed_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))
    error_message: Mapped[str | None] = mapped_column(Text)
    files_processed: Mapped[int] = mapped_column(Integer, default=0)
    files_total: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    ai_calls_made: Mapped[int] = mapped_column(Integer, default=0)

    project: Mapped["Project"] = relationship(back_populates="scans")
    config: Mapped["ScanConfig | None"] = relationship(
        back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEvent"]] = relationship(
        back_populates="scan", lazy="select", cascade="all, delete-orphan"
    )
    report: Mapped["Report | None"] = relationship(
        back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )


class ScanConfig(Base):
    __tablename__ = "scan_configs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), unique=True)
    scanners: Mapped[dict] = mapped_column(JSONB)
    semgrep_version: Mapped[str | None] = mapped_column(String(50))
    bandit_version: Mapped[str | None] = mapped_column(String(50))
    eslint_version: Mapped[str | None] = mapped_column(String(50))
    advisory_db_ver: Mapped[str | None] = mapped_column(String(50))
    llm_model: Mapped[str | None] = mapped_column(String(255))
    scan_mode: Mapped[str] = mapped_column(String(20))

    scan: Mapped["Scan"] = relationship(back_populates="config")


class ScanEvent(Base):
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), index=True)
    phase: Mapped[str | None] = mapped_column(String(50))
    level: Mapped[str] = mapped_column(String(10), default="info")
    message: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    scan: Mapped["Scan"] = relationship(back_populates="events")
