import uuid

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.db_types import JSONType


class Dependency(Base):
    __tablename__ = "dependencies"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(50))
    name: Mapped[str] = mapped_column(String(500))
    version: Mapped[str | None] = mapped_column(String(100))
    source_file: Mapped[str | None] = mapped_column(Text)
    is_dev: Mapped[bool] = mapped_column(default=False)


class DependencyFinding(Base):
    __tablename__ = "dependency_findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    dependency_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dependencies.id"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), index=True)
    advisory_id: Mapped[str | None] = mapped_column(String(100))
    cve_id: Mapped[str | None] = mapped_column(String(50))  # CVE-2024-XXXXX
    severity: Mapped[str | None] = mapped_column(String(20))
    cvss_score: Mapped[float | None] = mapped_column(Float)
    summary: Mapped[str | None] = mapped_column(Text)
    details: Mapped[str | None] = mapped_column(Text)  # Full vulnerability description
    affected_range: Mapped[str | None] = mapped_column(String(200))
    fixed_version: Mapped[str | None] = mapped_column(String(100))
    cwes: Mapped[list | None] = mapped_column(JSONType)  # ["CWE-79", "CWE-89"]
    references: Mapped[list | None] = mapped_column(JSONType)  # [urls]
    vulnerable_functions: Mapped[list | None] = mapped_column(JSONType)  # ["parse()", "load()"]
    evidence_type: Mapped[str] = mapped_column(String(40), default="exact_package_match")
    relevance: Mapped[str] = mapped_column(String(20), default="unknown")
    usage_evidence: Mapped[list | None] = mapped_column(JSONType)
    reachability_status: Mapped[str] = mapped_column(String(30), default="unknown")
    reachability_confidence: Mapped[float | None] = mapped_column(Float)
    risk_score: Mapped[float | None] = mapped_column(Float)
    risk_factors: Mapped[dict | None] = mapped_column(JSONType)
    ai_assessment: Mapped[str | None] = mapped_column(Text)
