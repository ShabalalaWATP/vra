"""Scan service — business logic for scan lifecycle management."""

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.scan import Scan


async def get_scan_stats(scan_id: uuid.UUID, db: AsyncSession) -> dict:
    """Get summary stats for a scan."""
    finding_counts = {}
    for severity in ("critical", "high", "medium", "low", "info"):
        result = await db.execute(
            select(func.count()).where(
                Finding.scan_id == scan_id, Finding.severity == severity
            )
        )
        count = result.scalar() or 0
        if count > 0:
            finding_counts[severity] = count

    return {
        "finding_counts": finding_counts,
        "total_findings": sum(finding_counts.values()),
    }
