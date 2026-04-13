from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.analysis.diagram import render_diagram_for_report
from app.models.report import Report

SVG_MARKER_RE = re.compile(br"<svg\b", re.IGNORECASE)

CANONICAL_DIAGRAM_ORDER = {
    "overview": 0,
    "security": 1,
    "data_flow": 2,
    "attack_surface": 3,
    "result_overview": 10,
    "trust_boundaries": 11,
    "dependency_risk": 12,
}


@dataclass(slots=True)
class RenderedReportDiagram:
    title: str
    description: str = ""
    kind: str | None = None
    highlights: list[str] = field(default_factory=list)
    mermaid: str = ""
    image_bytes: bytes | None = None
    media_type: str | None = None


def is_svg_bytes(data: bytes | None) -> bool:
    if not data:
        return False
    prefix = data.lstrip()[:256]
    return bool(SVG_MARKER_RE.search(prefix))


def guess_diagram_media_type(data: bytes | None) -> str | None:
    if not data:
        return None
    if is_svg_bytes(data):
        return "image/svg+xml"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    return "application/octet-stream"


def count_report_diagrams(report: Report) -> int:
    diagrams = extract_report_diagrams(report)
    if diagrams:
        return len(diagrams)
    return 1 if report.diagram_image else 0


def primary_diagram_media_type(report: Report) -> str | None:
    return guess_diagram_media_type(report.diagram_image)


def extract_report_diagrams(report: Report) -> list[dict[str, Any]]:
    payload = _parse_architecture_payload(report.architecture)
    diagrams = payload.get("diagrams")
    if isinstance(diagrams, list):
        normalised = [
            (index, _normalise_diagram_entry(item))
            for index, item in enumerate(diagrams)
        ]
        normalised = sorted(
            (
                (CANONICAL_DIAGRAM_ORDER.get(str(item.get("kind") or ""), 100), index, item)
                for index, item in normalised
                if item
            ),
            key=lambda row: (row[0], row[1]),
        )
        normalised = [item for _rank, _index, item in normalised]
        if normalised:
            return normalised

    if report.diagram_spec:
        return [
            {
                "title": "Architecture Overview",
                "description": "Primary report diagram.",
                "kind": "overview",
                "highlights": [],
                "mermaid": report.diagram_spec,
            }
        ]

    return []


async def render_report_diagram(
    report: Report,
    index: int,
    *,
    llm_client=None,
) -> RenderedReportDiagram | None:
    diagrams = extract_report_diagrams(report)
    if not diagrams:
        if index == 0 and report.diagram_image:
            return RenderedReportDiagram(
                title="Architecture Overview",
                description="Primary report diagram.",
                kind="overview",
                image_bytes=report.diagram_image,
                media_type=guess_diagram_media_type(report.diagram_image),
            )
        return None

    if index < 0 or index >= len(diagrams):
        return None

    diagram = diagrams[index]
    techs = _extract_report_techs(report)
    mermaid = str(diagram.get("mermaid") or "").strip()
    image_bytes: bytes | None = None
    if index == 0 and report.diagram_image:
        image_bytes = report.diagram_image
    elif mermaid:
        image_bytes = await render_diagram_for_report(
            mermaid,
            llm_client=llm_client,
            techs=techs,
        )

    return RenderedReportDiagram(
        title=str(diagram.get("title") or f"Architecture Diagram {index + 1}"),
        description=str(diagram.get("description") or ""),
        kind=str(diagram.get("kind") or "") or None,
        highlights=[
            str(item).strip()
            for item in (diagram.get("highlights") or [])
            if str(item).strip()
        ],
        mermaid=mermaid,
        image_bytes=image_bytes,
        media_type=guess_diagram_media_type(image_bytes),
    )


async def render_report_diagrams(report: Report, *, llm_client=None) -> list[RenderedReportDiagram]:
    diagrams = extract_report_diagrams(report)
    if diagrams:
        rendered: list[RenderedReportDiagram] = []
        for index in range(len(diagrams)):
            diagram = await render_report_diagram(report, index, llm_client=llm_client)
            if diagram:
                rendered.append(diagram)
        return rendered

    if report.diagram_image:
        return [
            RenderedReportDiagram(
                title="Architecture Overview",
                description="Primary report diagram.",
                kind="overview",
                image_bytes=report.diagram_image,
                media_type=guess_diagram_media_type(report.diagram_image),
            )
        ]

    return []


def svg_to_png_bytes(svg_bytes: bytes) -> bytes:
    try:
        import cairosvg
    except ImportError as exc:
        raise RuntimeError(
            "cairosvg is required to convert SVG diagrams for DOCX export"
        ) from exc
    return cairosvg.svg2png(bytestring=svg_bytes)


def _parse_architecture_payload(raw_payload: str | None) -> dict[str, Any]:
    if not raw_payload:
        return {}
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _normalise_diagram_entry(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    mermaid = str(entry.get("mermaid") or "").strip()
    if not mermaid:
        return None
    kind = _diagram_kind(str(entry.get("kind") or ""), str(entry.get("title") or ""))
    title = str(entry.get("title") or "Architecture Overview").strip()
    if kind == "overview":
        title = "System Overview"
    elif kind == "security":
        title = "Security Architecture"
    elif kind == "data_flow":
        title = "Data Flow"
    elif kind == "attack_surface":
        title = "Attack Surface"
    return {
        "title": title,
        "description": str(entry.get("description") or ""),
        "kind": kind or str(entry.get("kind") or ""),
        "highlights": [
            str(item).strip()
            for item in (entry.get("highlights") or [])
            if str(item).strip()
        ],
        "mermaid": mermaid,
    }


def _diagram_kind(raw_kind: str, title: str) -> str | None:
    kind = str(raw_kind or "").strip().lower().replace("-", "_").replace(" ", "_")
    if kind in CANONICAL_DIAGRAM_ORDER:
        return kind

    title_key = " ".join(str(title or "").strip().lower().split())
    title_map = {
        "system overview": "overview",
        "overview": "overview",
        "architecture overview": "overview",
        "system architecture": "overview",
        "security architecture": "security",
        "security overview": "security",
        "data flow": "data_flow",
        "dataflow": "data_flow",
        "attack surface": "attack_surface",
        "verified security overview": "result_overview",
        "trust boundaries and hotspots": "trust_boundaries",
        "dependency exposure and reachability": "dependency_risk",
    }
    return title_map.get(title_key)


def _extract_report_techs(report: Report) -> list[str]:
    tech_stack = report.tech_stack if isinstance(report.tech_stack, dict) else {}
    fingerprint = tech_stack.get("fingerprint")
    payload = fingerprint if isinstance(fingerprint, dict) else tech_stack

    techs: list[str] = []
    for key in ("languages", "frameworks"):
        values = payload.get(key) or tech_stack.get(key) or []
        for value in values:
            if isinstance(value, str):
                item = value.strip()
            elif isinstance(value, dict):
                item = str(value.get("name") or "").strip()
            else:
                item = str(value).strip()
            if item and item not in techs:
                techs.append(item)
    return techs
