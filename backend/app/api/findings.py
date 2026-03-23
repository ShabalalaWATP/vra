import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models.dependency import Dependency, DependencyFinding
from app.models.file import File
from app.models.finding import Evidence, Finding, FindingFile
from app.models.scanner_result import ScannerResult
from app.models.secret_candidate import SecretCandidate
from app.schemas.finding import (
    DependencyFindingOut,
    FindingOut,
    ScannerResultOut,
    SecretCandidateOut,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans/{scan_id}", tags=["findings"])


def _finding_to_out(f: Finding, file_path_map: dict[uuid.UUID, str]) -> FindingOut:
    file_paths = [file_path_map[ff.file_id] for ff in f.files if ff.file_id in file_path_map]
    return FindingOut(
        id=f.id,
        scan_id=f.scan_id,
        title=f.title,
        severity=f.severity,
        confidence=f.confidence,
        category=f.category,
        description=f.description,
        explanation=f.explanation,
        impact=f.impact,
        remediation=f.remediation,
        code_snippet=f.code_snippet,
        status=f.status,
        cwe_ids=f.cwe_ids,
        related_cves=f.related_cves,
        exploit_difficulty=f.exploit_difficulty,
        exploit_prerequisites=f.exploit_prerequisites,
        exploit_template=f.exploit_template,
        attack_scenario=f.attack_scenario,
        evidence=[
            {
                "id": e.id,
                "type": e.type,
                "description": e.description,
                "code_snippet": e.code_snippet,
                "line_range": e.line_range,
                "source": e.source,
            }
            for e in f.evidence
        ],
        file_paths=file_paths,
        created_at=f.created_at,
    )


@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    scan_id: uuid.UUID,
    severity: str | None = None,
    status: str | None = None,
    limit: int = Query(default=100, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(selectinload(Finding.evidence))
        .order_by(
            case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                (Finding.severity == "info", 4),
                else_=5,
            ),
            Finding.confidence.desc(),
        )
        .limit(limit)
    )
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)

    # Also eager-load file associations
    query = query.options(selectinload(Finding.files))

    result = await db.execute(query)
    findings = result.scalars().all()

    # Batch-load all file paths for all findings in one query (avoids N+1)
    all_file_ids = {ff.file_id for f in findings for ff in f.files}
    file_path_map: dict[uuid.UUID, str] = {}
    if all_file_ids:
        file_rows = await db.execute(select(File.id, File.path).where(File.id.in_(all_file_ids)))
        file_path_map = {row.id: row.path for row in file_rows.all()}

    out = []
    for f in findings:
        out.append(_finding_to_out(f, file_path_map))
    return out


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(
    scan_id: uuid.UUID, finding_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    result = await db.execute(
        select(Finding)
        .where(Finding.id == finding_id, Finding.scan_id == scan_id)
        .options(selectinload(Finding.evidence), selectinload(Finding.files))
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(404, "Finding not found")

    file_path_map: dict[uuid.UUID, str] = {}
    all_file_ids = {ff.file_id for ff in finding.files}
    if all_file_ids:
        file_rows = await db.execute(select(File.id, File.path).where(File.id.in_(all_file_ids)))
        file_path_map = {row.id: row.path for row in file_rows.all()}

    return _finding_to_out(finding, file_path_map)


@router.get("/secrets", response_model=list[SecretCandidateOut])
async def list_secrets(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(SecretCandidate).where(SecretCandidate.scan_id == scan_id)
    )
    candidates = result.scalars().all()
    file_ids = {s.file_id for s in candidates if s.file_id}
    file_path_map: dict[uuid.UUID, str] = {}
    if file_ids:
        file_rows = await db.execute(select(File.id, File.path).where(File.id.in_(file_ids)))
        file_path_map = {row.id: row.path for row in file_rows.all()}

    out = []
    for s in candidates:
        out.append(
            SecretCandidateOut(
                id=s.id,
                type=s.type,
                value_preview=s.value_preview,
                line_number=s.line_number,
                confidence=s.confidence,
                context=s.context,
                file_path=file_path_map.get(s.file_id) if s.file_id else None,
                is_false_positive=s.is_false_positive,
            )
        )
    return out


@router.get("/scanner-results", response_model=list[ScannerResultOut])
async def list_scanner_results(
    scan_id: uuid.UUID,
    scanner: str | None = None,
    severity: str | None = None,
    file_path: str | None = None,
    limit: int = Query(default=200, le=1000),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(ScannerResult, File.path)
        .outerjoin(File, ScannerResult.file_id == File.id)
        .where(ScannerResult.scan_id == scan_id)
        .order_by(ScannerResult.created_at.desc())
    )
    if scanner:
        query = query.where(ScannerResult.scanner == scanner)
    if severity:
        query = query.where(ScannerResult.severity == severity)
    if file_path:
        query = query.where(File.path == file_path)
    query = query.limit(limit)

    result = await db.execute(query)
    return [
        ScannerResultOut(
            id=sr.id,
            scanner=sr.scanner,
            rule_id=sr.rule_id,
            severity=sr.severity,
            message=sr.message,
            file_path=path,
            start_line=sr.start_line,
            end_line=sr.end_line,
            snippet=sr.snippet,
            metadata=sr.extra_data,
            created_at=sr.created_at,
        )
        for sr, path in result.all()
    ]


@router.get("/dependencies", response_model=list[DependencyFindingOut])
async def list_dependency_findings(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(DependencyFinding, Dependency)
        .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
        .where(DependencyFinding.scan_id == scan_id)
    )
    out = []
    for df, dep in result.all():
        out.append(
            DependencyFindingOut(
                id=df.id,
                package_name=dep.name,
                ecosystem=dep.ecosystem,
                installed_version=dep.version,
                advisory_id=df.advisory_id,
                severity=df.severity,
                cvss_score=df.cvss_score,
                summary=df.summary,
                affected_range=df.affected_range,
                fixed_version=df.fixed_version,
                relevance=df.relevance,
                ai_assessment=df.ai_assessment,
            )
        )
    return out


@router.post("/findings/backfill-files")
async def backfill_finding_files(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """One-time backfill: match findings to source files via code_snippet content matching."""
    from app.models.project import Project
    from app.models.scan import Scan

    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    project = await db.get(Project, scan.project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    # Load all files for this scan
    file_rows = (await db.execute(
        select(File).where(File.scan_id == scan_id)
    )).scalars().all()

    if not file_rows:
        return {"linked": 0, "message": "No files in scan"}

    # Build path→id map
    path_to_id: dict[str, uuid.UUID] = {f.path: f.id for f in file_rows}

    # Load all findings that have NO file associations
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .options(selectinload(Finding.files))
    )
    findings = findings_result.scalars().all()

    repo_path = Path(project.repo_path) if project.repo_path else None
    linked = 0

    for finding in findings:
        if finding.files:
            continue  # Already linked

        snippet = finding.code_snippet
        if not snippet or not repo_path:
            continue

        # Try to match snippet against actual file contents
        snippet_lines = snippet.strip().splitlines()
        if not snippet_lines:
            continue
        # Use first non-empty meaningful line for matching
        match_line = None
        for sl in snippet_lines:
            cleaned = sl.strip().strip(".")
            if len(cleaned) > 15 and not cleaned.startswith("//") and not cleaned.startswith("#"):
                match_line = cleaned
                break
        if not match_line:
            continue

        for file_path, file_id in path_to_id.items():
            try:
                full = repo_path / file_path
                if not full.exists() or full.stat().st_size > 500_000:
                    continue
                content = full.read_text(encoding="utf-8", errors="ignore")
                if match_line in content:
                    # Check if link already exists
                    existing = await db.execute(
                        select(FindingFile).where(
                            FindingFile.finding_id == finding.id,
                            FindingFile.file_id == file_id,
                        )
                    )
                    if not existing.scalar_one_or_none():
                        db.add(FindingFile(finding_id=finding.id, file_id=file_id))
                        linked += 1
                    break  # One file per finding is enough
            except Exception:
                continue

    await db.commit()
    return {"linked": linked, "total_findings": len(findings)}
