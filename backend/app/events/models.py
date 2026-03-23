import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class ScanEvent(BaseModel):
    scan_id: uuid.UUID
    phase: str | None = None
    level: Literal["debug", "info", "warn", "error"] = "info"
    message: str
    detail: dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ProgressUpdate(BaseModel):
    scan_id: uuid.UUID
    status: str
    phase: str | None = None
    task: str | None = None
    files_processed: int = 0
    files_total: int = 0
    findings_count: int = 0


class ScanCompleted(BaseModel):
    scan_id: uuid.UUID
    status: str  # completed or failed
    error: str | None = None
