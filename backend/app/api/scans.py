import asyncio
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.events.bus import event_bus
from app.models.llm_profile import LLMProfile
from app.models.project import Project
from app.models.scan import Scan, ScanConfig
from app.schemas.scan import ScanCreate, ScanEventOut, ScanOut
from app.scanners.registry import create_scanner_set

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

# Reference to the orchestrator runner — set during app startup
_run_scan_fn = None
_scan_tasks: dict[uuid.UUID, asyncio.Task] = {}

SCANNER_ALIASES = {
    "semgrep": "semgrep",
    "bandit": "bandit",
    "eslint": "eslint",
    "codeql": "codeql",
    "secrets": "secrets",
    "dependencies": "dep_audit",
    "dependency": "dep_audit",
    "dep_audit": "dep_audit",
}
DEFAULT_SCANNERS = {
    "semgrep": True,
    "bandit": True,
    "eslint": True,
    "codeql": True,
    "secrets": True,
    "dep_audit": True,
}

PROVENANCE_FIELDS = {
    "semgrep": "semgrep_version",
    "bandit": "bandit_version",
    "eslint": "eslint_version",
    "codeql": "codeql_version",
    "secrets": "secrets_version",
    "dep_audit": "advisory_db_ver",
}


def set_scan_runner(fn):
    global _run_scan_fn
    _run_scan_fn = fn


def _register_scan_task(scan_id: uuid.UUID, task: asyncio.Task) -> None:
    _scan_tasks[scan_id] = task


def _pop_scan_task(scan_id: uuid.UUID, task: asyncio.Task | None = None) -> asyncio.Task | None:
    existing = _scan_tasks.get(scan_id)
    if existing is None:
        return None
    if task is not None and existing is not task:
        return None
    return _scan_tasks.pop(scan_id, None)


def _scan_task_done(task: asyncio.Task, *, scan_id: uuid.UUID) -> None:
    """Callback for scan background task — logs unhandled exceptions."""
    _pop_scan_task(scan_id, task)
    if task.cancelled():
        logger.warning("Scan task %s was cancelled", scan_id)
        return
    exc = task.exception()
    if exc:
        logger.error("Scan task %s failed with unhandled exception: %s", scan_id, exc, exc_info=exc)


def normalise_scanner_config(raw: dict | None) -> dict[str, bool]:
    config = dict(DEFAULT_SCANNERS)
    if not raw:
        return config

    for key, value in raw.items():
        canonical = SCANNER_ALIASES.get(str(key).strip().lower())
        if not canonical:
            continue
        config[canonical] = bool(value)

    return config


async def collect_scan_provenance(
    scanner_config: dict[str, bool],
    *,
    llm_profile: LLMProfile | None = None,
) -> dict[str, str | None]:
    provenance = {field: None for field in PROVENANCE_FIELDS.values()}
    provenance["llm_model"] = llm_profile.model_name if llm_profile else None

    scanners = create_scanner_set()
    version_tasks: list = []
    version_fields: list[str] = []

    for scanner_name, field_name in PROVENANCE_FIELDS.items():
        if not scanner_config.get(scanner_name, False):
            continue
        scanner = scanners.get(scanner_name)
        if scanner is None:
            continue
        version_fields.append(field_name)
        version_tasks.append(scanner.get_version())

    if version_tasks:
        results = await asyncio.gather(*version_tasks, return_exceptions=True)
        for field_name, result in zip(version_fields, results):
            provenance[field_name] = None if isinstance(result, Exception) else result

    return provenance


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(body: ScanCreate, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, body.project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    llm_profile = None
    if body.llm_profile_id:
        llm_profile = await db.get(LLMProfile, body.llm_profile_id)
        if not llm_profile:
            raise HTTPException(404, "LLM profile not found")

    scan = Scan(
        project_id=body.project_id,
        llm_profile_id=body.llm_profile_id,
        mode=body.mode,
        status="pending",
    )
    db.add(scan)
    await db.flush()

    # Create config snapshot
    scanners = normalise_scanner_config(body.scanners)
    provenance = await collect_scan_provenance(scanners, llm_profile=llm_profile)
    config = ScanConfig(
        scan_id=scan.id,
        scanners=scanners,
        semgrep_version=provenance.get("semgrep_version"),
        bandit_version=provenance.get("bandit_version"),
        eslint_version=provenance.get("eslint_version"),
        codeql_version=provenance.get("codeql_version"),
        secrets_version=provenance.get("secrets_version"),
        advisory_db_ver=provenance.get("advisory_db_ver"),
        llm_model=provenance.get("llm_model"),
        scan_mode=body.mode,
    )
    db.add(config)
    await db.flush()

    return ScanOut.model_validate(scan)


@router.post("/{scan_id}/start", response_model=ScanOut)
async def start_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    # Use FOR UPDATE to prevent concurrent start requests
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id).with_for_update()
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != "pending":
        raise HTTPException(400, f"Scan is {scan.status}, cannot start")

    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.flush()

    # Launch the scan in background
    if _run_scan_fn:
        task = asyncio.create_task(_run_scan_fn(scan_id))
        _register_scan_task(scan_id, task)
        task.add_done_callback(lambda t: _scan_task_done(t, scan_id=scan_id))

    return ScanOut.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    # Use FOR UPDATE to prevent concurrent cancel/complete race
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id).with_for_update()
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != "running":
        raise HTTPException(400, f"Scan is {scan.status}, cannot cancel")

    scan.status = "cancelled"
    scan.current_task = None
    scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.flush()

    task = _pop_scan_task(scan_id)
    if task and not task.done():
        task.cancel()

    await event_bus.publish(
        scan_id,
        {
            "type": "progress",
            "status": "cancelled",
            "phase": scan.current_phase,
            "task": None,
            "findings_count": scan.findings_count,
            "files_processed": scan.files_processed,
            "files_total": scan.files_total,
            "ai_calls_made": scan.ai_calls_made,
        },
    )
    await event_bus.complete(scan_id)
    return ScanOut.model_validate(scan)


@router.get("", response_model=list[ScanOut])
async def list_scans(
    project_id: uuid.UUID | None = None, db: AsyncSession = Depends(get_db)
):
    query = select(Scan).order_by(Scan.created_at.desc())
    if project_id:
        query = query.where(Scan.project_id == project_id)
    result = await db.execute(query)
    return [ScanOut.model_validate(s) for s in result.scalars().all()]


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return ScanOut.model_validate(scan)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status == "running":
        raise HTTPException(400, "Cannot delete a running scan. Cancel it first.")

    # Delete all child records (no ORM cascade configured on Scan)
    from app.models.finding import Finding
    from app.models.file import File, FileSummary
    from app.models.scanner_result import ScannerResult
    from app.models.agent_decision import AgentDecision, CompactionSummary
    from app.models.report import Report
    from app.models.scan import ScanConfig
    from app.models.scan import ScanEvent
    from app.models.dependency import Dependency, DependencyFinding
    from app.models.secret_candidate import SecretCandidate
    from app.models.symbol import Symbol, Route

    for model in [
        Route, Symbol, FileSummary, ScannerResult, Finding, SecretCandidate,
        DependencyFinding, Dependency, AgentDecision, CompactionSummary,
        ScanEvent, Report, ScanConfig, File,
    ]:
        try:
            await db.execute(sa_delete(model).where(model.scan_id == scan_id))
        except Exception:
            pass  # Table may not exist yet

    await db.delete(scan)
    await db.flush()


@router.get("/{scan_id}/events", response_model=list[ScanEventOut])
async def get_scan_events(
    scan_id: uuid.UUID,
    after_id: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    from app.models.scan import ScanEvent

    result = await db.execute(
        select(ScanEvent)
        .where(ScanEvent.scan_id == scan_id, ScanEvent.id > after_id)
        .order_by(ScanEvent.id)
        .limit(limit)
    )
    return [ScanEventOut.model_validate(e) for e in result.scalars().all()]
