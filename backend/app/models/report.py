import uuid
from datetime import datetime, timezone

from sqlalchemy import Float, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base
from app.db_types import JSONType


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), unique=True)
    app_summary: Mapped[str | None] = mapped_column(Text)
    architecture: Mapped[str | None] = mapped_column(Text)
    diagram_spec: Mapped[str | None] = mapped_column(Text)
    diagram_image: Mapped[bytes | None] = mapped_column(LargeBinary)
    methodology: Mapped[str | None] = mapped_column(Text)
    limitations: Mapped[str | None] = mapped_column(Text)
    tech_stack: Mapped[dict | None] = mapped_column(JSONType)
    scanner_hits: Mapped[dict | None] = mapped_column(JSONType)
    attack_surface: Mapped[dict | None] = mapped_column(JSONType)
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_grade: Mapped[str | None] = mapped_column(String(2))
    owasp_mapping: Mapped[dict | None] = mapped_column(JSONType)
    component_scores: Mapped[dict | None] = mapped_column(JSONType)
    sbom: Mapped[dict | None] = mapped_column(JSONType)
    scan_coverage: Mapped[dict | None] = mapped_column(JSONType)
    narrative: Mapped[str | None] = mapped_column(Text)
    report_html: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    scan: Mapped["Scan"] = relationship(back_populates="report")
    exports: Mapped[list["ExportArtifact"]] = relationship(
        back_populates="report", lazy="selectin", cascade="all, delete-orphan"
    )


class ExportArtifact(Base):
    __tablename__ = "export_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("reports.id"))
    format: Mapped[str] = mapped_column(String(10))
    file_path: Mapped[str] = mapped_column(Text)
    file_size: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))

    report: Mapped["Report"] = relationship(back_populates="exports")
