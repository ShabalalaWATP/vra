import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.report import ExportArtifact, Report
from app.schemas.report import ExportOut, ExportRequest, ReportOut

router = APIRouter(prefix="/scans/{scan_id}/report", tags=["reports"])


@router.get("", response_model=ReportOut)
async def get_report(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not found")
    return ReportOut(
        id=report.id,
        scan_id=report.scan_id,
        app_summary=report.app_summary,
        architecture=report.architecture,
        diagram_spec=report.diagram_spec,
        has_diagram_image=report.diagram_image is not None,
        methodology=report.methodology,
        limitations=report.limitations,
        tech_stack=report.tech_stack,
        scanner_hits=report.scanner_hits,
        attack_surface=report.attack_surface,
        risk_score=report.risk_score,
        risk_grade=report.risk_grade,
        owasp_mapping=report.owasp_mapping,
        component_scores=report.component_scores,
        sbom=report.sbom,
        scan_coverage=report.scan_coverage,
        created_at=report.created_at,
    )


@router.get("/diagram")
async def get_diagram(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalar_one_or_none()
    if not report or not report.diagram_image:
        raise HTTPException(404, "Diagram not found")
    from fastapi.responses import Response

    return Response(content=report.diagram_image, media_type="image/svg+xml")


@router.post("/export", response_model=ExportOut)
async def export_report(
    scan_id: uuid.UUID, body: ExportRequest, db: AsyncSession = Depends(get_db)
):
    if body.format not in ("pdf", "docx"):
        raise HTTPException(400, "Format must be pdf or docx")

    result = await db.execute(select(Report).where(Report.scan_id == scan_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not found")

    from app.services.export_service import generate_export

    artifact = await generate_export(report, body.format, db)
    return ExportOut.model_validate(artifact)


@router.get("/export/{artifact_id}/download")
async def download_export(
    scan_id: uuid.UUID, artifact_id: uuid.UUID, db: AsyncSession = Depends(get_db)
):
    artifact = await db.get(ExportArtifact, artifact_id)
    if not artifact:
        raise HTTPException(404, "Export not found")

    # Validate the artifact belongs to a report for this scan
    report = await db.get(Report, artifact.report_id)
    if not report or report.scan_id != scan_id:
        raise HTTPException(404, "Export not found for this scan")

    from pathlib import Path
    if not Path(artifact.file_path).exists():
        raise HTTPException(404, "Export file not found on disk")

    media = "application/pdf" if artifact.format == "pdf" else (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    return FileResponse(
        artifact.file_path,
        media_type=media,
        filename=f"report.{artifact.format}",
    )
