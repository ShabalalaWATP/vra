"""Offline diagram rendering — convert Mermaid specs to SVG/PNG with embedded tech icons.

Strategies (tried in order):
1. mermaid-cli (mmdc) if installed — best quality
2. LLM-generated SVG with embedded icons — good for air-gapped
3. Plaintext fallback with tech legend — always works

Icons are loaded from data/icons/svg/ (downloaded via scripts/download_icons.py).
"""

import asyncio
import json
import logging
import re
import shutil
import tempfile
from pathlib import Path

from app.analysis.icons import (
    create_icon_legend_svg,
    get_icon_data_uri,
    has_icon,
)

logger = logging.getLogger(__name__)


# ── Mermaid config for dark theme with icons ─────────────────────

MERMAID_DARK_CONFIG = json.dumps({
    "theme": "dark",
    "themeVariables": {
        "darkMode": True,
        "background": "#1a1a2e",
        "primaryColor": "#16213e",
        "primaryTextColor": "#e0e0e0",
        "primaryBorderColor": "#00d4ff",
        "lineColor": "#64ffda",
        "secondaryColor": "#0f3460",
        "tertiaryColor": "#111128",
        "fontFamily": "Inter, Segoe UI, sans-serif",
        "fontSize": "14px",
        "nodeBorder": "#00d4ff",
        "clusterBkg": "#111128",
        "clusterBorder": "#2a2a4a",
        "edgeLabelBackground": "#16213e",
    },
})


async def render_mermaid_to_svg(
    mermaid_spec: str,
    *,
    config: str | None = None,
) -> bytes | None:
    """
    Render a Mermaid diagram spec to SVG bytes.
    Returns None if rendering is not possible.
    """
    cfg = config or MERMAID_DARK_CONFIG

    # Strategy 1: mermaid-cli (mmdc) — best quality
    mmdc = shutil.which("mmdc") or shutil.which("mermaid")
    if mmdc:
        return await _render_with_mmdc(mmdc, mermaid_spec, cfg)

    # Strategy 2: npx fallback
    npx = shutil.which("npx")
    if npx:
        return await _render_with_npx(npx, mermaid_spec, cfg)

    return None


async def _render_with_mmdc(mmdc_path: str, spec: str, config: str) -> bytes | None:
    """Render using mermaid-cli (mmdc)."""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "diagram.mmd"
            output_file = Path(tmpdir) / "diagram.svg"
            config_file = Path(tmpdir) / "config.json"

            input_file.write_text(spec, encoding="utf-8")
            config_file.write_text(config, encoding="utf-8")

            proc = await asyncio.create_subprocess_exec(
                mmdc_path,
                "-i", str(input_file),
                "-o", str(output_file),
                "-c", str(config_file),
                "-b", "transparent",
                "--quiet",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)

            if output_file.exists():
                return output_file.read_bytes()

        logger.warning("mmdc produced no output")
        return None
    except Exception as e:
        logger.warning("mmdc rendering failed: %s", e)
        return None


async def _render_with_npx(npx_path: str, spec: str, config: str) -> bytes | None:
    """Render using npx @mermaid-js/mermaid-cli."""
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_file = Path(tmpdir) / "diagram.mmd"
            output_file = Path(tmpdir) / "diagram.svg"
            config_file = Path(tmpdir) / "config.json"

            input_file.write_text(spec, encoding="utf-8")
            config_file.write_text(config, encoding="utf-8")

            proc = await asyncio.create_subprocess_exec(
                npx_path, "--yes", "@mermaid-js/mermaid-cli",
                "-i", str(input_file),
                "-o", str(output_file),
                "-c", str(config_file),
                "-b", "transparent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=60)

            if output_file.exists():
                return output_file.read_bytes()

        logger.warning("npx mermaid-cli produced no output")
        return None
    except Exception as e:
        logger.warning("npx rendering failed: %s", e)
        return None


# ── Icon-enriched SVG rendering ──────────────────────────────────

def _render_fallback_svg(
    spec: str,
    techs: list[str] | None = None,
) -> bytes:
    """
    Generate an SVG that shows the Mermaid source with a tech icon legend.
    Always works offline — no external tools needed.
    """
    lines = spec.strip().splitlines()
    line_height = 18
    padding = 24
    max_line_len = max((len(line) for line in lines), default=40)
    spec_width = max(max_line_len * 8 + padding * 2, 600)

    # Build the icon legend if we have techs
    legend_height = 0
    legend_svg = ""
    if techs:
        available_techs = [t for t in techs if has_icon(t)]
        if available_techs:
            legend_svg = create_icon_legend_svg(
                available_techs,
                icon_size=20,
                spacing=12,
                color="#e0e0e0",
                label_color="#a0a0b0",
                bg_color="#16213e",
            )
            # Estimate legend dimensions
            cols = min(len(available_techs), 8)
            rows = (len(available_techs) + cols - 1) // cols
            legend_height = rows * 36 + 24

    spec_height = len(lines) * line_height + padding * 2
    total_height = spec_height + legend_height + (20 if legend_height else 0)
    width = max(spec_width, 600)

    # Title
    parts = [
        f'<?xml version="1.0" encoding="UTF-8"?>',
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'xmlns:xlink="http://www.w3.org/1999/xlink" '
        f'width="{width}" height="{total_height}" '
        f'viewBox="0 0 {width} {total_height}">',
        f'<rect width="100%" height="100%" fill="#1a1a2e" rx="8"/>',
    ]

    # Icon legend at the top
    if legend_svg and legend_height:
        parts.append(f'<g transform="translate({padding}, {padding})">')
        # Strip the outer <svg> from the legend and embed the inner content
        inner = re.sub(r'<\/?svg[^>]*>', '', legend_svg)
        parts.append(inner)
        parts.append('</g>')

    # Diagram title
    title_y = padding + legend_height + (12 if legend_height else 0)
    parts.append(
        f'<text x="{padding}" y="{title_y}" fill="#00d4ff" '
        f'font-family="Inter, sans-serif" font-size="14" font-weight="600">'
        f'Architecture Diagram</text>'
    )

    # Mermaid source
    for i, line in enumerate(lines):
        escaped = (
            line.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        y = title_y + 24 + (i * line_height)
        parts.append(
            f'<text x="{padding}" y="{y}" fill="#a0a0b0" '
            f'font-family="Consolas, monospace" font-size="12">{escaped}</text>'
        )

    parts.append('</svg>')
    return "\n".join(parts).encode("utf-8")


# ── Public API ───────────────────────────────────────────────────

async def render_diagram_for_report(
    mermaid_spec: str,
    llm_client=None,
    techs: list[str] | None = None,
) -> bytes:
    """
    Render a diagram for report embedding.

    Priority:
    1. Real Mermaid rendering (mmdc/npx)
    2. LLM-generated SVG with embedded icons
    3. Fallback SVG with tech icon legend + Mermaid source

    Args:
        mermaid_spec: Mermaid diagram source
        llm_client: Optional LLM client for AI SVG generation
        techs: List of technology names for icon legend
    """
    if not mermaid_spec or not mermaid_spec.strip():
        return _render_fallback_svg("(No architecture diagram generated)", techs)

    # Strategy 1: Real Mermaid rendering
    svg = await render_mermaid_to_svg(mermaid_spec)
    if svg:
        # Append icon legend below the rendered diagram if we have techs
        if techs:
            svg = _append_icon_legend(svg, techs)
        return svg

    # Strategy 2: LLM-generated SVG with icon hints
    if llm_client:
        try:
            icon_hints = _build_icon_hints(techs or [])
            svg_text = await llm_client.chat_text(
                system=(
                    "You are a diagram renderer. Convert the following Mermaid diagram "
                    "specification into a clean SVG image.\n\n"
                    "Theme requirements:\n"
                    "- Background: #1a1a2e\n"
                    "- Box fill: #16213e with border #00d4ff\n"
                    "- Text color: #e0e0e0\n"
                    "- Arrow/line color: #64ffda\n"
                    "- Font: Inter, sans-serif\n"
                    "- Rounded corners (rx=8) on boxes\n\n"
                    f"{icon_hints}\n\n"
                    "Output ONLY valid SVG markup. No explanation."
                ),
                user=f"Convert to SVG:\n\n{mermaid_spec}",
                max_tokens=6000,
            )
            if "<svg" in svg_text:
                start = svg_text.index("<svg")
                end = svg_text.rindex("</svg>") + len("</svg>")
                result = svg_text[start:end].encode("utf-8")
                if techs:
                    result = _append_icon_legend(result, techs)
                return result
        except Exception as e:
            logger.warning("LLM SVG generation failed: %s", e)

    # Strategy 3: Fallback with icon legend
    return _render_fallback_svg(mermaid_spec, techs)


def _build_icon_hints(techs: list[str]) -> str:
    """Build icon data URI hints the LLM can embed in its SVG output."""
    hints = []
    for tech in techs:
        uri = get_icon_data_uri(tech, color="#e0e0e0")
        if uri:
            hints.append(
                f'For "{tech}", use this icon: '
                f'<image width="20" height="20" href="{uri}"/>'
            )

    if not hints:
        return ""

    return (
        "You may embed these technology icons in the diagram nodes "
        "using <image> tags with the provided data URIs:\n"
        + "\n".join(hints[:10])  # Limit to avoid prompt bloat
    )


def _append_icon_legend(svg_bytes: bytes, techs: list[str]) -> bytes:
    """Append a tech icon legend below an existing SVG diagram."""
    available = [t for t in techs if has_icon(t)]
    if not available:
        return svg_bytes

    legend = create_icon_legend_svg(
        available,
        icon_size=20,
        spacing=12,
        color="#e0e0e0",
        label_color="#a0a0b0",
        bg_color="#16213e",
    )
    if not legend:
        return svg_bytes

    # Parse the outer SVG dimensions and extend height
    svg_text = svg_bytes.decode("utf-8", errors="replace")

    # Find existing height
    height_match = re.search(r'height="(\d+)"', svg_text)
    if not height_match:
        return svg_bytes

    old_height = int(height_match.group(1))
    cols = min(len(available), 8)
    rows = (len(available) + cols - 1) // cols
    legend_h = rows * 36 + 40
    new_height = old_height + legend_h

    # Update height
    svg_text = svg_text.replace(
        f'height="{old_height}"',
        f'height="{new_height}"',
    )

    # Update viewBox if present
    vb_match = re.search(r'viewBox="([^"]*)"', svg_text)
    if vb_match:
        vb_parts = vb_match.group(1).split()
        if len(vb_parts) == 4:
            vb_parts[3] = str(new_height)
            svg_text = svg_text.replace(
                f'viewBox="{vb_match.group(1)}"',
                f'viewBox="{" ".join(vb_parts)}"',
            )

    # Insert legend before closing </svg>
    legend_inner = re.sub(r'<\/?svg[^>]*>', '', legend)
    legend_group = (
        f'<g transform="translate(20, {old_height + 10})">'
        f'<text x="0" y="0" fill="#00d4ff" font-family="Inter, sans-serif" '
        f'font-size="12" font-weight="600">Technology Stack</text>'
        f'<g transform="translate(0, 12)">{legend_inner}</g>'
        f'</g>'
    )

    svg_text = svg_text.replace('</svg>', f'{legend_group}\n</svg>')
    return svg_text.encode("utf-8")
