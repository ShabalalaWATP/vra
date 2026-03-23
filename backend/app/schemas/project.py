import uuid
from datetime import datetime

from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None
    repo_path: str


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    repo_path: str | None = None


class ProjectOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    repo_path: str
    source_type: str = "codebase"  # codebase, apk, aab
    created_at: datetime
    updated_at: datetime
    scan_count: int = 0

    model_config = {"from_attributes": True}
