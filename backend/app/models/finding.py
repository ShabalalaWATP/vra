import uuid
from datetime import datetime, timezone

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), index=True)
    title: Mapped[str] = mapped_column(String(500))
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float)
    category: Mapped[str | None] = mapped_column(String(100))
    description: Mapped[str] = mapped_column(Text)
    explanation: Mapped[str | None] = mapped_column(Text)
    impact: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    code_snippet: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), default="confirmed")
    cwe_ids: Mapped[list | None] = mapped_column(JSONB)
    related_cves: Mapped[list | None] = mapped_column(JSONB)  # [{cve_id, summary, severity, package, fixed_version}]
    # Exploit evidence
    exploit_difficulty: Mapped[str | None] = mapped_column(String(20))
    exploit_prerequisites: Mapped[list | None] = mapped_column(JSONB)
    exploit_template: Mapped[str | None] = mapped_column(Text)
    attack_scenario: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="finding", lazy="selectin", cascade="all, delete-orphan"
    )
    files: Mapped[list["FindingFile"]] = relationship(
        lazy="selectin", cascade="all, delete-orphan"
    )


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    file_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("files.id"))
    type: Mapped[str] = mapped_column(String(20))  # supporting, opposing, contextual
    description: Mapped[str] = mapped_column(Text)
    code_snippet: Mapped[str | None] = mapped_column(Text)
    line_range: Mapped[str | None] = mapped_column(String(50))
    source: Mapped[str | None] = mapped_column(String(50))
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    finding: Mapped["Finding"] = relationship(back_populates="evidence")


class FindingFile(Base):
    __tablename__ = "finding_files"

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), primary_key=True)
    file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("files.id"), primary_key=True)
