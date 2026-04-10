"""Report export — Professional PDF and DOCX generation.

Smart finding presentation:
- CRITICAL & HIGH: Full detail (description, code, impact, remediation, PoC)
- MEDIUM: Concise summary (title, description, CWE — no code blocks)
- LOW & INFO: Table-only (title, severity, category)

Code snippets capped at 4 lines. Reports stay under 30 pages.
"""

import io
import json
import uuid
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.dependency import Dependency, DependencyFinding
from app.models.finding import Evidence, Finding
from app.models.report import ExportArtifact, Report
from app.models.secret_candidate import SecretCandidate

MAX_CODE_LINES = 4
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _truncate_code(snippet: str | None, max_lines: int = MAX_CODE_LINES) -> str:
    if not snippet:
        return ""
    lines = snippet.strip().splitlines()
    if len(lines) <= max_lines:
        return snippet.strip()
    return "\n".join(lines[:max_lines]) + f"\n... ({len(lines) - max_lines} more lines)"


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -(f.confidence or 0)))


def _truncate_text(value: str | None, max_chars: int) -> str:
    if not value:
        return ""
    text = value.strip()
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3].rstrip() + "..."


def _sort_dependency_findings(dep_findings: list[tuple[DependencyFinding, Dependency]]) -> list[tuple[DependencyFinding, Dependency]]:
    return sorted(
        dep_findings,
        key=lambda item: (
            item[0].risk_score is None,
            -(item[0].risk_score or 0.0),
            SEVERITY_ORDER.get((item[0].severity or "info").lower(), 9),
            item[1].name.lower(),
        ),
    )


def _humanise_dependency_label(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("_", " ").strip().title()


def _format_dependency_risk_score(score: float | None) -> str:
    return f"{round(score)}/1000" if score is not None else "n/a"


def _format_dependency_exposure(df: DependencyFinding) -> str:
    reachability = _humanise_dependency_label(df.reachability_status)
    if reachability and df.reachability_confidence is not None:
        reachability = f"{reachability} ({round(df.reachability_confidence * 100)}%)"

    parts = [
        _humanise_dependency_label(df.relevance),
        reachability,
        _humanise_dependency_label(df.evidence_type),
    ]
    return " | ".join(part for part in parts if part)


def _summarise_dependency_usage(usage_evidence: list | None, limit: int = 2) -> str:
    if not usage_evidence:
        return ""

    kind_labels = {
        "import": "import",
        "reference": "reference",
        "vulnerable_function": "vulnerable function",
    }
    parts: list[str] = []
    for hit in usage_evidence[:limit]:
        if not isinstance(hit, dict):
            continue
        label = kind_labels.get(str(hit.get("kind", "")), _humanise_dependency_label(str(hit.get("kind", "usage"))).lower())
        symbol = str(hit.get("symbol", "")).strip()
        location = str(hit.get("file", "")).strip()
        line = hit.get("line")
        if location and isinstance(line, int):
            location = f"{location}:{line}"
        summary = label
        if symbol:
            summary += f" {symbol}"
        if location:
            summary += f" in {location}"
        parts.append(summary)

    return "; ".join(part for part in parts if part)


def _summarise_dependency_risk_factors(risk_factors: dict | None, limit: int = 3) -> str:
    if not isinstance(risk_factors, dict):
        return ""

    labels = {
        "reachability": "reachability",
        "relevance": "package usage",
        "vulnerable_function_match": "function match",
        "dev_dependency": "dev-only scope",
        "fix_available": "fix available",
        "hot_file_usage": "hot-file usage",
    }
    items = [
        (key, value)
        for key, value in risk_factors.items()
        if key not in {"base", "final"} and isinstance(value, (int, float)) and value != 0
    ]
    items.sort(key=lambda item: abs(float(item[1])), reverse=True)
    return ", ".join(
        f"{labels.get(key, _humanise_dependency_label(key).lower())} {'+' if value > 0 else ''}{round(float(value))}"
        for key, value in items[:limit]
    )


def _format_dependency_notes(df: DependencyFinding) -> str:
    notes: list[str] = []
    if df.ai_assessment:
        notes.append(_truncate_text(df.ai_assessment, 180))
    elif df.summary:
        notes.append(_truncate_text(df.summary, 180))

    usage = _summarise_dependency_usage(df.usage_evidence)
    if usage:
        notes.append(f"Usage: {usage}")

    if df.vulnerable_functions:
        notes.append(f"Functions: {', '.join(df.vulnerable_functions[:3])}")

    factors = _summarise_dependency_risk_factors(df.risk_factors)
    if factors:
        notes.append(f"Factors: {factors}")

    if df.fixed_version:
        notes.append(f"Fix: {df.fixed_version}")

    return " ".join(note for note in notes if note)


def _format_related_advisory(advisory: dict) -> str:
    advisory_id = (
        advisory.get("display_id")
        or advisory.get("cve_id")
        or advisory.get("advisory_id")
        or "advisory"
    )
    parts = [str(advisory_id)]

    severity = str(advisory.get("severity") or "").strip()
    if severity:
        parts.append(severity.upper())

    package = str(advisory.get("package") or "").strip()
    ecosystem = str(advisory.get("ecosystem") or "").strip()
    if package:
        package_label = package
        if ecosystem:
            package_label += f" ({ecosystem})"
        parts.append(package_label)

    evidence_strength = str(advisory.get("evidence_strength") or "").strip()
    evidence_type = str(advisory.get("evidence_type") or "").strip()
    evidence_bits = [bit for bit in [
        _humanise_dependency_label(evidence_strength),
        _humanise_dependency_label(evidence_type),
    ] if bit]
    if evidence_bits:
        parts.append(", ".join(evidence_bits))

    if advisory.get("import_module"):
        parts.append(f"import {advisory['import_module']}")
    if advisory.get("function"):
        function_label = f"call {advisory['function']}"
        if isinstance(advisory.get("line"), int):
            function_label += f" line {advisory['line']}"
        parts.append(function_label)
    if advisory.get("fixed_version"):
        parts.append(f"fix {advisory['fixed_version']}")

    summary = _truncate_text(str(advisory.get("summary") or "").strip(), 120)
    if summary:
        parts.append(summary)

    return " | ".join(part for part in parts if part)


def _format_related_advisories(advisories: list | None, limit: int = 3) -> list[str]:
    if not advisories:
        return []
    lines: list[str] = []
    for advisory in advisories[:limit]:
        if isinstance(advisory, dict):
            lines.append(_format_related_advisory(advisory))
    return [line for line in lines if line]


async def generate_export(report: Report, format: str, db: AsyncSession) -> ExportArtifact:
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == report.scan_id).order_by(Finding.severity)
    )
    findings = _sort_findings(findings_result.scalars().all())

    secrets_result = await db.execute(
        select(SecretCandidate).where(
            SecretCandidate.scan_id == report.scan_id,
            SecretCandidate.is_false_positive == False,
        )
    )
    secrets = secrets_result.scalars().all()

    dep_findings_result = await db.execute(
        select(DependencyFinding, Dependency)
        .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
        .where(DependencyFinding.scan_id == report.scan_id)
    )
    dep_findings = _sort_dependency_findings(dep_findings_result.all())

    report_data = {
        "report": report,
        "findings": findings,
        "secrets": secrets,
        "dep_findings": dep_findings,
    }

    settings.export_dir.mkdir(parents=True, exist_ok=True)
    file_name = f"vragent_report_{report.scan_id}.{format}"
    file_path = settings.export_dir / file_name

    if format == "docx":
        await _generate_docx(report_data, file_path)
    elif format == "pdf":
        await _generate_pdf(report_data, file_path)

    artifact = ExportArtifact(
        report_id=report.id,
        format=format,
        file_path=str(file_path),
        file_size=file_path.stat().st_size if file_path.exists() else 0,
    )
    db.add(artifact)
    await db.flush()
    return artifact


# ══════════════════════════════════════════════════════════════════
# DOCX GENERATION
# ══════════════════════════════════════════════════════════════════

async def _generate_docx(data: dict, output_path: Path):
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor, Cm
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT

    doc = Document()
    report: Report = data["report"]
    findings: list[Finding] = data["findings"]
    secrets = data["secrets"]
    dep_findings = data["dep_findings"]

    # Style defaults
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)
    style.paragraph_format.space_after = Pt(4)

    section_num = 0
    def sec():
        nonlocal section_num
        section_num += 1
        return section_num

    # Split findings by severity tier
    critical_high = [f for f in findings if f.severity in ("critical", "high")]
    medium = [f for f in findings if f.severity == "medium"]
    low_info = [f for f in findings if f.severity in ("low", "info")]

    # ── Cover Page ─────────────────────────────────────────────
    doc.add_paragraph()  # spacing
    doc.add_paragraph()
    title = doc.add_heading("Security Assessment Report", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    if report.app_summary:
        # Extract first line as app name
        first_line = report.app_summary.split("\n")[0].strip()
        if len(first_line) < 100:
            sub = doc.add_paragraph()
            sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = sub.add_run(first_line)
            run.font.size = Pt(14)
            run.font.color.rgb = RGBColor(0x33, 0x33, 0x33)

    doc.add_paragraph()
    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    meta.add_run(f"Generated: {datetime.now().strftime('%d %B %Y')}\n").font.size = Pt(10)
    meta.add_run("VRAgent — AI-Assisted Vulnerability Research Platform").font.size = Pt(9)

    if report.risk_grade:
        doc.add_paragraph()
        grade_p = doc.add_paragraph()
        grade_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = grade_p.add_run(f"Risk Grade: {report.risk_grade}")
        run.bold = True
        run.font.size = Pt(24)
        grade_colors = {"A": 0x155724, "B": 0x0C5460, "C": 0x856404, "D": 0xE67E22, "F": 0xDC3545}
        run.font.color.rgb = RGBColor(*_int_to_rgb(grade_colors.get(report.risk_grade, 0x333333)))
        grade_p.add_run(f"  ({report.risk_score:.0f}/100)").font.size = Pt(14)

    doc.add_page_break()

    # ── Executive Summary ──────────────────────────────────────
    n = sec()
    doc.add_heading(f"{n}. Executive Summary", level=1)

    grade_text = {
        "A": "No significant security issues identified. The application demonstrates strong security practices.",
        "B": "Minor issues found with low overall risk. Recommended to address findings in the next development cycle.",
        "C": "Moderate security concerns requiring attention. Several vulnerabilities should be addressed before production deployment.",
        "D": "Significant security issues discovered. Remediation is strongly recommended before production use.",
        "F": "Critical security failures identified. Immediate remediation is required. The application should not be deployed in its current state.",
    }
    if report.risk_grade:
        doc.add_paragraph(grade_text.get(report.risk_grade, ""))

    # Key metrics
    p = doc.add_paragraph()
    p.add_run("Key Metrics: ").bold = True
    p.add_run(
        f"{len(findings)} findings total — "
        f"{len([f for f in findings if f.severity == 'critical'])} Critical, "
        f"{len([f for f in findings if f.severity == 'high'])} High, "
        f"{len(medium)} Medium, "
        f"{len(low_info)} Low/Info"
    )
    exploitable = [f for f in findings if f.exploit_template]
    if exploitable:
        p = doc.add_paragraph()
        p.add_run(f"Exploitable findings with PoC: ").bold = True
        p.add_run(str(len(exploitable)))

    advisory_count = len([f for f in findings if f.related_cves])
    if advisory_count:
        p = doc.add_paragraph()
        p.add_run(f"Findings with advisory correlations: ").bold = True
        p.add_run(str(advisory_count))

    # ── Application Overview ───────────────────────────────────
    n = sec()
    doc.add_heading(f"{n}. Application Overview", level=1)
    if report.app_summary:
        for para in report.app_summary.split("\n"):
            if para.strip():
                doc.add_paragraph(para.strip())

    if report.tech_stack:
        tech = report.tech_stack if isinstance(report.tech_stack, dict) else {}
        fp = tech.get("fingerprint", tech)
        langs = fp.get("languages", tech.get("languages", []))
        fws = fp.get("frameworks", tech.get("frameworks", []))
        if langs:
            items = langs if isinstance(langs[0], str) else [f"{l['name']} ({l['file_count']} files)" for l in langs]
            doc.add_paragraph(f"Languages: {', '.join(items)}")
        if fws:
            items = fws if isinstance(fws[0], str) else [f['name'] for f in fws]
            doc.add_paragraph(f"Frameworks: {', '.join(items)}")

    # ── Architecture ───────────────────────────────────────────
    if report.diagram_image:
        n = sec()
        doc.add_heading(f"{n}. Architecture", level=1)
        try:
            doc.add_picture(io.BytesIO(report.diagram_image), width=Inches(6.5))
            doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        except Exception:
            doc.add_paragraph("[Diagram could not be embedded]")

    # ── Critical & High Findings (Full Detail) ─────────────────
    n = sec()
    doc.add_heading(f"{n}. Critical & High Severity Findings ({len(critical_high)})", level=1)

    if not critical_high:
        doc.add_paragraph("No critical or high severity findings were identified.")
    else:
        for i, f in enumerate(critical_high, 1):
            doc.add_heading(f"{n}.{i}. {f.title}", level=2)

            # Metadata line
            p = doc.add_paragraph()
            sev_run = p.add_run(f"{f.severity.upper()}")
            sev_run.bold = True
            sev_run.font.color.rgb = RGBColor(0xDC, 0x35, 0x45) if f.severity == "critical" else RGBColor(0xE6, 0x7E, 0x22)
            p.add_run(f"  |  Confidence: {f.confidence:.0%}")
            if f.cwe_ids:
                p.add_run(f"  |  {', '.join(f.cwe_ids[:3])}")
            if f.category:
                p.add_run(f"  |  {f.category}")

            if f.description:
                doc.add_paragraph(f.description[:600])

            if f.code_snippet:
                code_p = doc.add_paragraph()
                run = code_p.add_run(_truncate_code(f.code_snippet))
                run.font.name = "Consolas"
                run.font.size = Pt(8)
                run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

            if f.impact:
                p = doc.add_paragraph()
                p.add_run("Impact: ").bold = True
                p.add_run(f.impact[:300])

            if f.remediation:
                p = doc.add_paragraph()
                p.add_run("Remediation: ").bold = True
                p.add_run(f.remediation[:300])

            if f.exploit_difficulty:
                p = doc.add_paragraph()
                p.add_run(f"Exploit Difficulty: ").bold = True
                p.add_run(f.exploit_difficulty.upper())

            if f.attack_scenario:
                p = doc.add_paragraph()
                p.add_run("Attack Scenario: ").bold = True
                p.add_run(f.attack_scenario[:400])

            if f.exploit_template:
                doc.add_heading("Proof of Concept", level=3)
                code_p = doc.add_paragraph()
                run = code_p.add_run(_truncate_code(f.exploit_template, 6))
                run.font.name = "Consolas"
                run.font.size = Pt(8)
                run.font.color.rgb = RGBColor(0x99, 0x33, 0x33)

            if f.related_cves:
                p = doc.add_paragraph()
                p.add_run("Related advisories: ").bold = True
                advisory_lines = _format_related_advisories(f.related_cves, limit=3)
                p.add_run(" ; ".join(advisory_lines))

    # ── Medium Findings (Concise) ──────────────────────────────
    if medium:
        n = sec()
        doc.add_heading(f"{n}. Medium Severity Findings ({len(medium)})", level=1)

        table = doc.add_table(rows=1, cols=5)
        table.style = "Light Grid Accent 1"
        for i, h in enumerate(["#", "Title", "Category", "CWE", "Confidence"]):
            table.rows[0].cells[i].text = h

        for i, f in enumerate(medium, 1):
            row = table.add_row().cells
            row[0].text = str(i)
            row[1].text = f.title[:80]
            row[2].text = f.category or ""
            row[3].text = ", ".join(f.cwe_ids[:2]) if f.cwe_ids else ""
            row[4].text = f"{f.confidence:.0%}"

        doc.add_paragraph()
        # Brief descriptions for medium findings (no code)
        for i, f in enumerate(medium, 1):
            if f.description:
                p = doc.add_paragraph()
                p.add_run(f"{i}. {f.title}: ").bold = True
                p.add_run(f.description[:200])

    # ── Low & Info Findings (Table Only) ───────────────────────
    if low_info:
        n = sec()
        doc.add_heading(f"{n}. Low & Informational Findings ({len(low_info)})", level=1)
        doc.add_paragraph("These findings represent low-risk issues or informational observations.")

        table = doc.add_table(rows=1, cols=4)
        table.style = "Light Grid Accent 1"
        for i, h in enumerate(["Title", "Severity", "Category", "Confidence"]):
            table.rows[0].cells[i].text = h
        for f in low_info:
            row = table.add_row().cells
            row[0].text = f.title[:80]
            row[1].text = f.severity.upper()
            row[2].text = f.category or ""
            row[3].text = f"{f.confidence:.0%}"

    # ── OWASP Top 10 ──────────────────────────────────────────
    if report.owasp_mapping:
        n = sec()
        doc.add_heading(f"{n}. OWASP Top 10 Mapping", level=1)
        table = doc.add_table(rows=1, cols=4)
        table.style = "Light Grid Accent 1"
        for i, h in enumerate(["Code", "Category", "Findings", "Max Severity"]):
            table.rows[0].cells[i].text = h
        for code in ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"]:
            entry = report.owasp_mapping.get(code)
            if entry and entry.get("count", 0) > 0:
                row = table.add_row().cells
                row[0].text = code
                row[1].text = entry.get("name", "")
                row[2].text = str(entry["count"])
                row[3].text = entry.get("max_severity", "").upper()

    # ── Component Scorecard ────────────────────────────────────
    if report.component_scores:
        n = sec()
        doc.add_heading(f"{n}. Component Security Scorecard", level=1)
        doc.add_paragraph(
            "Components are graded A-F based on finding density and severity. "
            "A = no findings, B = low-severity only, C = medium findings present, "
            "D = high-severity findings, F = critical findings detected."
        )
        table = doc.add_table(rows=1, cols=5)
        table.style = "Light Grid Accent 1"
        for i, h in enumerate(["Component", "Grade", "Score", "Criticality", "Findings"]):
            table.rows[0].cells[i].text = h
        for name, comp in sorted(report.component_scores.items(), key=lambda x: x[1]["score"]):
            row = table.add_row().cells
            row[0].text = name
            row[1].text = comp["grade"]
            row[2].text = str(comp["score"])
            row[3].text = comp.get("criticality", "")
            row[4].text = str(comp["finding_count"])

    # ── Secrets ────────────────────────────────────────────────
    if secrets:
        n = sec()
        doc.add_heading(f"{n}. Secrets & Sensitive Data ({len(secrets)})", level=1)
        table = doc.add_table(rows=1, cols=3)
        table.style = "Light Grid Accent 1"
        for i, h in enumerate(["Type", "File", "Confidence"]):
            table.rows[0].cells[i].text = h
        for s in secrets[:30]:
            row = table.add_row().cells
            row[0].text = s.type
            row[1].text = (s.file_path or "")[:60]
            row[2].text = f"{s.confidence:.0%}" if s.confidence else ""
        if len(secrets) > 30:
            doc.add_paragraph(f"... and {len(secrets) - 30} additional secrets detected.")

    # ── Dependencies ───────────────────────────────────────────
    if dep_findings:
        n = sec()
        doc.add_heading(f"{n}. Dependency Risks ({len(dep_findings)})", level=1)
        reachable = sum(1 for df, _ in dep_findings if df.reachability_status == "reachable")
        active = sum(1 for df, _ in dep_findings if df.relevance in {"used", "likely_used"})
        doc.add_paragraph(
            "Dependency issues are ranked by combined risk score rather than advisory severity alone. "
            f"{reachable} are marked reachable and {active} show direct or likely package usage."
        )

        table = doc.add_table(rows=1, cols=6)
        table.style = "Light Grid Accent 1"
        for i, h in enumerate(["Package", "Advisory", "Severity", "Exposure", "Risk", "Notes"]):
            table.rows[0].cells[i].text = h
        for df, dep in dep_findings[:20]:
            row = table.add_row().cells
            row[0].text = f"{dep.name}\n{dep.version or 'unknown'} ({dep.ecosystem})"
            row[1].text = df.cve_id or df.advisory_id or ""
            row[2].text = (df.severity or "").upper()
            row[3].text = _format_dependency_exposure(df)
            row[4].text = _format_dependency_risk_score(df.risk_score)
            row[5].text = _truncate_text(_format_dependency_notes(df) or "No package usage context captured.", 220)
        if len(dep_findings) > 20:
            doc.add_paragraph(f"... and {len(dep_findings) - 20} additional dependency risks.")

    # ── Scan Coverage ─────────────────────────────────────────
    if report.scan_coverage:
        cov = report.scan_coverage
        n = sec()
        doc.add_heading(f"{n}. Scan Coverage", level=1)
        p = doc.add_paragraph()
        p.add_run("Files scanned: ").bold = True
        p.add_run(f"{cov.get('total_files', 0)}")
        p = doc.add_paragraph()
        p.add_run("AI inspected: ").bold = True
        p.add_run(f"{cov.get('files_inspected_by_ai', 0)}")
        p = doc.add_paragraph()
        p.add_run("AI calls made: ").bold = True
        p.add_run(f"{cov.get('ai_calls_made', 0)}")
        p = doc.add_paragraph()
        p.add_run("Scan mode: ").bold = True
        p.add_run(f"{cov.get('scan_mode', '?')}")
        if cov.get("scanners_used"):
            p = doc.add_paragraph()
            p.add_run("Scanners: ").bold = True
            p.add_run(", ".join(cov["scanners_used"]))

    # ── Methodology ────────────────────────────────────────────
    n = sec()
    doc.add_heading(f"{n}. Methodology & Limitations", level=1)
    if report.methodology:
        doc.add_paragraph(report.methodology[:1500])
    if report.limitations:
        doc.add_heading("Limitations", level=2)
        doc.add_paragraph(report.limitations[:800])

    # ── Charts ─────────────────────────────────────────────────
    chart_images = _render_charts(report, findings)
    if chart_images:
        n = sec()
        doc.add_heading(f"{n}. Analytics", level=1)
        for chart_name, img_bytes in chart_images.items():
            try:
                doc.add_paragraph(chart_name)
                doc.add_picture(io.BytesIO(img_bytes), width=Inches(4.5))
                doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
            except Exception:
                pass

    doc.save(str(output_path))


def _int_to_rgb(val: int) -> tuple:
    return ((val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF)


# ══════════════════════════════════════════════════════════════════
# PDF GENERATION (HTML → WeasyPrint)
# ══════════════════════════════════════════════════════════════════

async def _generate_pdf(data: dict, output_path: Path):
    import asyncio
    html = _render_report_html(data)

    def _render():
        from weasyprint import HTML
        HTML(string=html).write_pdf(str(output_path))

    await asyncio.to_thread(_render)


def _render_report_html(data: dict) -> str:
    report: Report = data["report"]
    findings: list[Finding] = data["findings"]
    secrets = data["secrets"]
    dep_findings = data["dep_findings"]

    critical_high = [f for f in findings if f.severity in ("critical", "high")]
    medium = [f for f in findings if f.severity == "medium"]
    low_info = [f for f in findings if f.severity in ("low", "info")]

    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<style>",
        "@page { size: A4; margin: 2cm; @bottom-center { content: 'Page ' counter(page) ' of ' counter(pages); font-size: 8px; color: #999; } }",
        "body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; color: #1a1a2e; font-size: 10.5px; line-height: 1.6; }",
        "h1 { color: #0a3d62; border-bottom: 3px solid #0a3d62; padding-bottom: 8px; font-size: 22px; margin-top: 30px; }",
        "h2 { color: #1e6b8a; margin-top: 28px; font-size: 16px; border-bottom: 1px solid #e0e0e0; padding-bottom: 4px; }",
        "h3 { color: #2d6a4f; font-size: 13px; margin-top: 20px; }",
        "table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9.5px; page-break-inside: auto; }",
        "th, td { border: 1px solid #ddd; padding: 5px 8px; text-align: left; }",
        "th { background: #0a3d62; color: white; font-weight: 600; font-size: 9px; text-transform: uppercase; letter-spacing: 0.3px; }",
        "tr:nth-child(even) { background: #f8f9fa; }",
        "tr { page-break-inside: avoid; }",
        "pre, code { font-family: 'Consolas', 'Courier New', monospace; font-size: 8.5px; }",
        "pre { background: #f5f5f5; padding: 8px 12px; border-radius: 4px; border-left: 3px solid #0a3d62; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }",
        ".cover { text-align: center; page-break-after: always; padding-top: 120px; }",
        ".cover h1 { border: none; font-size: 32px; color: #0a3d62; }",
        ".cover .subtitle { font-size: 16px; color: #555; margin: 10px 0 40px; }",
        ".cover .meta { font-size: 11px; color: #888; }",
        ".grade-box { display: inline-block; font-size: 36px; font-weight: 900; width: 60px; height: 60px; line-height: 60px; text-align: center; border-radius: 12px; margin: 20px 0; }",
        ".grade-A { background: #d4edda; color: #155724; } .grade-B { background: #d1ecf1; color: #0c5460; }",
        ".grade-C { background: #fff3cd; color: #856404; } .grade-D { background: #ffeeba; color: #856404; }",
        ".grade-F { background: #f8d7da; color: #721c24; }",
        ".sev-critical { color: #dc3545; font-weight: 700; } .sev-high { color: #e67e22; font-weight: 700; }",
        ".sev-medium { color: #f39c12; font-weight: 600; } .sev-low { color: #27ae60; } .sev-info { color: #3498db; }",
        ".finding-card { border: 1px solid #e0e0e0; border-radius: 6px; padding: 14px; margin: 12px 0; page-break-inside: avoid; background: #fafafa; }",
        ".finding-card h3 { margin-top: 0; border: none; padding: 0; }",
        ".meta-line { font-size: 9.5px; color: #555; margin: 4px 0 8px; }",
        ".poc-block { background: #fff0f0; border-left: 3px solid #dc3545; }",
        "img { max-width: 100%; height: auto; }",
        ".page-break { page-break-before: always; }",
        "hr { border: none; border-top: 1px solid #e0e0e0; margin: 20px 0; }",
        "</style></head><body>",
    ]

    section = [0]
    def sec():
        section[0] += 1
        return section[0]

    # ── Cover Page ─────────────────────────────────────────────
    parts.append("<div class='cover'>")
    parts.append("<h1>Security Assessment Report</h1>")
    if report.app_summary:
        first_line = report.app_summary.split("\n")[0].strip()
        if len(first_line) < 100:
            parts.append(f"<div class='subtitle'>{_esc(first_line)}</div>")
    if report.risk_grade:
        parts.append(f"<div class='grade-box grade-{report.risk_grade}'>{report.risk_grade}</div>")
        parts.append(f"<div style='font-size:14px;'>Score: {report.risk_score:.0f}/100</div>")
    parts.append(f"<div class='meta'>Generated: {datetime.now().strftime('%d %B %Y')}<br>")
    parts.append("VRAgent — AI-Assisted Vulnerability Research Platform</div>")
    parts.append("</div>")

    # ── Executive Summary ──────────────────────────────────────
    n = sec()
    parts.append(f"<h1>{n}. Executive Summary</h1>")

    grade_text = {
        "A": "No significant security issues identified.",
        "B": "Minor issues found with low overall risk.",
        "C": "Moderate security concerns requiring attention.",
        "D": "Significant security issues. Remediation recommended before production.",
        "F": "Critical security failures. Immediate remediation required.",
    }
    if report.risk_grade:
        parts.append(f"<p>{grade_text.get(report.risk_grade, '')}</p>")

    parts.append(f"<p><strong>Total Findings:</strong> {len(findings)} — "
                 f"<span class='sev-critical'>{len([f for f in findings if f.severity == 'critical'])} Critical</span>, "
                 f"<span class='sev-high'>{len([f for f in findings if f.severity == 'high'])} High</span>, "
                 f"<span class='sev-medium'>{len(medium)} Medium</span>, "
                 f"{len(low_info)} Low/Info</p>")

    exploitable = [f for f in findings if f.exploit_template]
    if exploitable:
        parts.append(f"<p><strong>Exploitable (PoC available):</strong> {len(exploitable)}</p>")

    # ── Application Overview ───────────────────────────────────
    n = sec()
    parts.append(f"<h1>{n}. Application Overview</h1>")
    if report.app_summary:
        for para in report.app_summary.split("\n"):
            if para.strip():
                parts.append(f"<p>{_esc(para)}</p>")

    # ── Architecture ───────────────────────────────────────────
    if report.diagram_image:
        import base64
        n = sec()
        parts.append(f"<h1>{n}. Architecture</h1>")
        b64 = base64.b64encode(report.diagram_image).decode("ascii")
        parts.append(f'<img src="data:image/png;base64,{b64}" style="max-width:100%; margin:10px 0;">')

    # ── Critical & High Findings ───────────────────────────────
    n = sec()
    parts.append(f"<h1>{n}. Critical & High Severity Findings ({len(critical_high)})</h1>")

    if not critical_high:
        parts.append("<p>No critical or high severity findings were identified.</p>")
    else:
        for i, f in enumerate(critical_high, 1):
            parts.append("<div class='finding-card'>")
            sev_class = f"sev-{f.severity}"
            parts.append(f"<h3>{n}.{i}. {_esc(f.title)}</h3>")
            meta = f"<span class='{sev_class}'>{f.severity.upper()}</span>"
            meta += f" &nbsp;|&nbsp; Confidence: {f.confidence:.0%}"
            if f.cwe_ids:
                meta += f" &nbsp;|&nbsp; {', '.join(f.cwe_ids[:3])}"
            if f.category:
                meta += f" &nbsp;|&nbsp; {_esc(f.category)}"
            parts.append(f"<div class='meta-line'>{meta}</div>")

            if f.description:
                parts.append(f"<p>{_esc(f.description[:600])}</p>")
            if f.code_snippet:
                parts.append(f"<pre><code>{_esc(_truncate_code(f.code_snippet))}</code></pre>")
            if f.impact:
                parts.append(f"<p><strong>Impact:</strong> {_esc(f.impact[:300])}</p>")
            if f.remediation:
                parts.append(f"<p><strong>Remediation:</strong> {_esc(f.remediation[:300])}</p>")
            if f.exploit_difficulty:
                parts.append(f"<p><strong>Exploit Difficulty:</strong> {f.exploit_difficulty.upper()}</p>")
            if f.attack_scenario:
                parts.append(f"<p><strong>Attack Scenario:</strong> {_esc(f.attack_scenario[:400])}</p>")
            if f.exploit_template:
                parts.append(f"<p><strong>Proof of Concept:</strong></p>")
                parts.append(f"<pre class='poc-block'><code>{_esc(_truncate_code(f.exploit_template, 6))}</code></pre>")
            if f.related_cves:
                advisory_lines = ", ".join(_esc(line) for line in _format_related_advisories(f.related_cves, limit=3))
                parts.append(f"<p><strong>Related advisories:</strong> {advisory_lines}</p>")
            parts.append("</div>")

    # ── Medium Findings ────────────────────────────────────────
    if medium:
        n = sec()
        parts.append(f"<h1>{n}. Medium Severity Findings ({len(medium)})</h1>")
        parts.append("<table><tr><th>#</th><th>Title</th><th>Category</th><th>CWE</th><th>Confidence</th></tr>")
        for i, f in enumerate(medium, 1):
            cwe_str = ", ".join(f.cwe_ids[:2]) if f.cwe_ids else ""
            parts.append(f"<tr><td>{i}</td><td>{_esc(f.title[:80])}</td><td>{_esc(f.category or '')}</td><td>{cwe_str}</td><td>{f.confidence:.0%}</td></tr>")
        parts.append("</table>")

        for i, f in enumerate(medium, 1):
            if f.description:
                parts.append(f"<p><strong>{i}. {_esc(f.title[:60])}:</strong> {_esc(f.description[:200])}</p>")

    # ── Low & Info ─────────────────────────────────────────────
    if low_info:
        n = sec()
        parts.append(f"<h1>{n}. Low & Informational ({len(low_info)})</h1>")
        parts.append("<table><tr><th>Title</th><th>Severity</th><th>Category</th><th>Confidence</th></tr>")
        for f in low_info:
            parts.append(f"<tr><td>{_esc(f.title[:80])}</td><td class='sev-{f.severity}'>{f.severity.upper()}</td><td>{_esc(f.category or '')}</td><td>{f.confidence:.0%}</td></tr>")
        parts.append("</table>")

    # ── OWASP ──────────────────────────────────────────────────
    if report.owasp_mapping:
        n = sec()
        parts.append(f"<h1>{n}. OWASP Top 10 Mapping</h1>")
        parts.append("<table><tr><th>Code</th><th>Category</th><th>Count</th><th>Max Severity</th></tr>")
        for code in ["A01","A02","A03","A04","A05","A06","A07","A08","A09","A10"]:
            entry = report.owasp_mapping.get(code)
            if entry and entry.get("count", 0) > 0:
                parts.append(f"<tr><td><strong>{code}</strong></td><td>{_esc(entry['name'])}</td><td>{entry['count']}</td><td class='sev-{entry['max_severity']}'>{entry['max_severity'].upper()}</td></tr>")
        parts.append("</table>")

    # ── Component Scorecard ────────────────────────────────────
    if report.component_scores:
        n = sec()
        parts.append(f"<h1>{n}. Component Security Scorecard</h1>")
        parts.append("<p style='font-size:9px; color:#666;'>Grading: A = no findings, B = low-severity only, C = medium findings, D = high-severity, F = critical findings</p>")
        parts.append("<table><tr><th>Component</th><th>Grade</th><th>Score</th><th>Criticality</th><th>Findings</th></tr>")
        for name, comp in sorted(report.component_scores.items(), key=lambda x: x[1]["score"]):
            parts.append(f"<tr><td>{_esc(name)}</td><td><strong>{comp['grade']}</strong></td><td>{comp['score']}</td><td>{comp.get('criticality','')}</td><td>{comp['finding_count']}</td></tr>")
        parts.append("</table>")

    # ── Secrets ─────────────────────────────────────────────────
    if secrets:
        n = sec()
        parts.append(f"<h1>{n}. Secrets & Sensitive Data ({len(secrets)})</h1>")
        parts.append("<table><tr><th>Type</th><th>File</th><th>Confidence</th></tr>")
        for s in secrets[:30]:
            conf = f"{s.confidence:.0%}" if s.confidence else ""
            parts.append(f"<tr><td>{_esc(s.type)}</td><td>{_esc((s.file_path or '')[:60])}</td><td>{conf}</td></tr>")
        parts.append("</table>")
        if len(secrets) > 30:
            parts.append(f"<p><em>... and {len(secrets) - 30} additional secrets</em></p>")

    # ── Dependencies ────────────────────────────────────────────
    if dep_findings:
        n = sec()
        parts.append(f"<h1>{n}. Dependency Risks ({len(dep_findings)})</h1>")
        reachable = sum(1 for df, _ in dep_findings if df.reachability_status == "reachable")
        active = sum(1 for df, _ in dep_findings if df.relevance in {"used", "likely_used"})
        parts.append(
            "<p>Dependency issues are ranked by combined risk score rather than advisory severity alone. "
            f"{reachable} are marked reachable and {active} show direct or likely package usage.</p>"
        )
        parts.append("<table><tr><th>Package</th><th>Advisory</th><th>Severity</th><th>Exposure</th><th>Risk</th><th>Notes</th></tr>")
        for df, dep in dep_findings[:20]:
            notes = _truncate_text(_format_dependency_notes(df) or "No package usage context captured.", 220)
            package = _esc(f"{dep.name} ({dep.version or 'unknown'} | {dep.ecosystem})")
            parts.append(
                f"<tr><td>{package}</td>"
                f"<td>{_esc(df.cve_id or df.advisory_id or '')}</td>"
                f"<td class='sev-{df.severity or 'info'}'>{(df.severity or '').upper()}</td>"
                f"<td>{_esc(_format_dependency_exposure(df))}</td>"
                f"<td>{_esc(_format_dependency_risk_score(df.risk_score))}</td>"
                f"<td>{_esc(notes)}</td></tr>"
            )
        parts.append("</table>")
        if len(dep_findings) > 20:
            parts.append(f"<p><em>... and {len(dep_findings) - 20} additional risks</em></p>")

    # ── Scan Coverage ──────────────────────────────────────────
    if report.scan_coverage:
        cov = report.scan_coverage
        n = sec()
        parts.append(f"<h1>{n}. Scan Coverage</h1>")
        parts.append(f"<p><strong>Files:</strong> {cov.get('total_files', 0)} &nbsp;|&nbsp; <strong>AI inspected:</strong> {cov.get('files_inspected_by_ai', 0)} &nbsp;|&nbsp; <strong>AI calls:</strong> {cov.get('ai_calls_made', 0)} &nbsp;|&nbsp; <strong>Mode:</strong> {cov.get('scan_mode', '?')}</p>")
        if cov.get("scanners_used"):
            parts.append(f"<p><strong>Scanners:</strong> {', '.join(cov['scanners_used'])}</p>")

    # ── Methodology ────────────────────────────────────────────
    n = sec()
    parts.append(f"<h1>{n}. Methodology & Limitations</h1>")
    if report.methodology:
        parts.append(f"<p>{_esc(report.methodology[:1500])}</p>")
    if report.limitations:
        parts.append(f"<p><strong>Limitations:</strong> {_esc(report.limitations[:800])}</p>")

    # ── Charts ─────────────────────────────────────────────────
    chart_images = _render_charts(report, findings)
    if chart_images:
        import base64 as _b64
        n = sec()
        parts.append(f"<h1 class='page-break'>{n}. Analytics</h1>")
        parts.append("<div style='display:flex; flex-wrap:wrap; gap:20px; justify-content:center;'>")
        for chart_name, img_bytes in chart_images.items():
            b64 = _b64.b64encode(img_bytes).decode("ascii")
            parts.append(f"<div style='text-align:center;'><img src='data:image/png;base64,{b64}' style='max-width:320px;'><p style='font-size:9px; color:#666;'>{_esc(chart_name)}</p></div>")
        parts.append("</div>")

    parts.append("<hr><p style='text-align:center; color:#aaa; font-size:8px;'>Generated by VRAgent — AI-Assisted Vulnerability Research Platform</p>")
    parts.append("</body></html>")
    return "\n".join(parts)


def _esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


# ══════════════════════════════════════════════════════════════════
# CHART RENDERING (matplotlib)
# ══════════════════════════════════════════════════════════════════

SEV_COLORS = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e", "info": "#06b6d4"}
SCANNER_COLORS = {"semgrep": "#06b6d4", "bandit": "#f59e0b", "eslint": "#8b5cf6", "codeql": "#ec4899", "secrets": "#ef4444", "dep_audit": "#22c55e"}


def _render_charts(report: Report, findings: list) -> dict[str, bytes]:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return {}

    charts: dict[str, bytes] = {}
    plt.rcParams.update({"figure.facecolor": "white", "axes.facecolor": "white", "font.size": 9, "font.family": "sans-serif"})

    # 1. Severity donut
    if findings:
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        if sev_counts:
            fig, ax = plt.subplots(figsize=(4, 3))
            labels = list(sev_counts.keys())
            sizes = list(sev_counts.values())
            colors = [SEV_COLORS.get(s, "#999") for s in labels]
            ax.pie(sizes, labels=[s.title() for s in labels], colors=colors, autopct="%1.0f%%", startangle=90, pctdistance=0.8, wedgeprops={"width": 0.4, "edgecolor": "white", "linewidth": 1.5})
            ax.set_title("Severity Breakdown", fontsize=11, fontweight="bold", pad=12)
            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
            plt.close(fig)
            charts["Severity Breakdown"] = buf.getvalue()

    # 2. Scanner hits
    if report.scanner_hits:
        hits = {k: v for k, v in report.scanner_hits.items() if v > 0}
        if hits:
            fig, ax = plt.subplots(figsize=(4.5, 2.5))
            names = list(hits.keys())
            values = list(hits.values())
            colors = [SCANNER_COLORS.get(n, "#666") for n in names]
            bars = ax.barh([n.replace("_", " ").title() for n in names], values, color=colors, edgecolor="white", linewidth=0.5, height=0.6)
            ax.set_title("Scanner Hit Distribution", fontsize=11, fontweight="bold")
            ax.set_xlabel("Hits")
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)
            for bar, val in zip(bars, values):
                ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2, str(val), va="center", fontsize=8)
            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
            plt.close(fig)
            charts["Scanner Hits"] = buf.getvalue()

    # 3. Confidence distribution
    if findings:
        buckets = {"90-100%": 0, "70-89%": 0, "50-69%": 0, "<50%": 0}
        for f in findings:
            pct = f.confidence * 100
            if pct >= 90: buckets["90-100%"] += 1
            elif pct >= 70: buckets["70-89%"] += 1
            elif pct >= 50: buckets["50-69%"] += 1
            else: buckets["<50%"] += 1
        nonzero = {k: v for k, v in buckets.items() if v > 0}
        if nonzero:
            fig, ax = plt.subplots(figsize=(3.5, 3))
            ax.pie(list(nonzero.values()), labels=list(nonzero.keys()), colors=["#ef4444","#f97316","#eab308","#22c55e"][:len(nonzero)], autopct="%1.0f%%", startangle=90, wedgeprops={"edgecolor": "white", "linewidth": 1.5})
            ax.set_title("Confidence Distribution", fontsize=11, fontweight="bold", pad=12)
            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
            plt.close(fig)
            charts["Confidence Distribution"] = buf.getvalue()

    # 4. Attack surface radar
    if report.attack_surface and len(report.attack_surface) >= 3:
        import numpy as np
        categories = list(report.attack_surface.keys())
        values = list(report.attack_surface.values())
        max_val = max(values) if values else 1
        normalized = [v / max_val * 100 for v in values]
        N = len(categories)
        angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
        normalized += normalized[:1]
        angles += angles[:1]
        fig, ax = plt.subplots(figsize=(4, 4), subplot_kw=dict(polar=True))
        ax.fill(angles, normalized, alpha=0.15, color="#06b6d4")
        ax.plot(angles, normalized, color="#06b6d4", linewidth=2)
        ax.scatter(angles[:-1], normalized[:-1], color="#06b6d4", s=30, zorder=5)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, fontsize=7)
        ax.set_yticklabels([])
        ax.set_title("Attack Surface", fontsize=11, fontweight="bold", pad=20)
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
        plt.close(fig)
        charts["Attack Surface"] = buf.getvalue()

    return charts
