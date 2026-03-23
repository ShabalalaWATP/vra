import asyncio
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete as sa_delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.project import Project
from app.models.scan import Scan, ScanConfig
from app.schemas.scan import ScanCreate, ScanEventOut, ScanOut

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

# Reference to the orchestrator runner — set during app startup
_run_scan_fn = None


def set_scan_runner(fn):
    global _run_scan_fn
    _run_scan_fn = fn


def _scan_task_done(task: asyncio.Task, *, scan_id: uuid.UUID) -> None:
    """Callback for scan background task — logs unhandled exceptions."""
    if task.cancelled():
        logger.warning("Scan task %s was cancelled", scan_id)
        return
    exc = task.exception()
    if exc:
        logger.error("Scan task %s failed with unhandled exception: %s", scan_id, exc, exc_info=exc)


@router.post("", response_model=ScanOut, status_code=201)
async def create_scan(body: ScanCreate, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, body.project_id)
    if not project:
        raise HTTPException(404, "Project not found")

    scan = Scan(
        project_id=body.project_id,
        llm_profile_id=body.llm_profile_id,
        mode=body.mode,
        status="pending",
    )
    db.add(scan)
    await db.flush()

    # Create config snapshot
    scanners = body.scanners or {
        "semgrep": True,
        "bandit": True,
        "eslint": True,
        "secrets": True,
        "dependencies": True,
    }
    config = ScanConfig(
        scan_id=scan.id,
        scanners=scanners,
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
    scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    await db.flush()
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
