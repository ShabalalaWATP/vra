"""Tests for triage scanner run summaries."""

from app.orchestrator.agents.triage import TriageAgent
from app.scanners.base import ScannerHit, ScannerOutput


def test_scanner_summary_completed_when_successful_without_errors():
    output = ScannerOutput(
        scanner_name="semgrep",
        success=True,
        hits=[ScannerHit("rule", "high", "msg", "app.py", 1)],
        errors=[],
        duration_ms=123,
    )

    summary = TriageAgent.scanner_summary(output)

    assert summary["status"] == "completed"
    assert summary["hit_count"] == 1
    assert summary["duration_ms"] == 123


def test_scanner_summary_degraded_when_successful_with_errors():
    output = ScannerOutput(
        scanner_name="semgrep",
        success=True,
        hits=[],
        errors=["rule parse failed"],
        duration_ms=50,
    )

    summary = TriageAgent.scanner_summary(output)

    assert summary["status"] == "degraded"
    assert summary["errors"] == ["rule parse failed"]


def test_scanner_summary_failed_when_unsuccessful():
    output = ScannerOutput(
        scanner_name="eslint",
        success=False,
        hits=[],
        errors=["launcher failed"],
        duration_ms=10,
    )

    summary = TriageAgent.scanner_summary(output)

    assert summary["status"] == "failed"
    assert summary["success"] is False
