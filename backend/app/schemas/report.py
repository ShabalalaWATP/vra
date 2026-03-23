import uuid
from datetime import datetime

from pydantic import BaseModel


class ReportOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    app_summary: str | None
    architecture: str | None
    diagram_spec: str | None
    has_diagram_image: bool = False
    narrative: str | None = None
    methodology: str | None
    limitations: str | None
    tech_stack: dict | None
    scanner_hits: dict | None = None
    attack_surface: dict | None = None
    risk_score: float | None = None
    risk_grade: str | None = None
    owasp_mapping: dict | None = None
    component_scores: dict | None = None
    sbom: dict | None = None
    scan_coverage: dict | None = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ExportRequest(BaseModel):
    format: str  # pdf or docx


class ExportOut(BaseModel):
    id: uuid.UUID
    format: str
    file_path: str
    file_size: int | None
    created_at: datetime

    model_config = {"from_attributes": True}
