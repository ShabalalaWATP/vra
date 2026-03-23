import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ScanCreate(BaseModel):
    project_id: uuid.UUID
    llm_profile_id: uuid.UUID | None = None
    mode: Literal["light", "regular", "heavy"] = "regular"
    scanners: dict | None = None  # Override scanner selection


class ScanOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    llm_profile_id: uuid.UUID | None = None
    mode: str
    status: str
    current_phase: str | None
    current_task: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    error_message: str | None
    files_processed: int = 0
    files_total: int = 0
    findings_count: int = 0
    progress: float = 0.0
    ai_calls_made: int = 0

    model_config = {"from_attributes": True}


class ScanEventOut(BaseModel):
    id: int
    phase: str | None
    level: str
    message: str
    detail: dict | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanProgress(BaseModel):
    scan_id: uuid.UUID
    status: str
    phase: str | None
    task: str | None
    files_processed: int = 0
    files_total: int = 0
    findings_count: int = 0
    elapsed_seconds: float = 0
