import uuid
from datetime import datetime

from pydantic import BaseModel


class EvidenceOut(BaseModel):
    id: uuid.UUID
    type: str
    description: str
    code_snippet: str | None
    line_range: str | None
    source: str | None

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    severity: str
    confidence: float
    category: str | None
    description: str
    explanation: str | None
    impact: str | None
    remediation: str | None
    code_snippet: str | None
    status: str
    cwe_ids: list[str] | None = None
    related_cves: list[dict] | None = None
    exploit_difficulty: str | None = None
    exploit_prerequisites: list | None = None
    exploit_template: str | None = None
    attack_scenario: str | None = None
    evidence: list[EvidenceOut] = []
    file_paths: list[str] = []
    created_at: datetime

    model_config = {"from_attributes": True}


class SecretCandidateOut(BaseModel):
    id: uuid.UUID
    type: str
    value_preview: str | None
    line_number: int | None
    confidence: float | None
    context: str | None
    file_path: str | None
    is_false_positive: bool

    model_config = {"from_attributes": True}


class DependencyFindingOut(BaseModel):
    id: uuid.UUID
    package_name: str
    ecosystem: str
    installed_version: str | None
    advisory_id: str | None
    severity: str | None
    cvss_score: float | None
    summary: str | None
    affected_range: str | None
    fixed_version: str | None
    vulnerable_functions: list[str] | None = None
    evidence_type: str
    relevance: str
    usage_evidence: list[dict] | None = None
    reachability_status: str
    reachability_confidence: float | None = None
    risk_score: float | None = None
    risk_factors: dict | None = None
    ai_assessment: str | None

    model_config = {"from_attributes": True}


class ScannerResultOut(BaseModel):
    id: uuid.UUID
    scanner: str
    rule_id: str | None
    severity: str | None
    message: str | None
    file_path: str | None
    start_line: int | None
    end_line: int | None
    snippet: str | None
    metadata: dict | None = None
    created_at: datetime

    model_config = {"from_attributes": True}
