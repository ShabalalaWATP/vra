"""File tree and content API for the codebase browser."""

import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.file import File
from app.models.project import Project
from app.models.scan import Scan

router = APIRouter(prefix="/scans/{scan_id}", tags=["files"])

MAX_FILE_SIZE = 500_000  # 500KB cap for browser display


def _build_tree(file_records: list[dict]) -> list[dict]:
    """Build hierarchical tree from flat file paths."""
    root: dict = {"name": "", "path": "", "type": "dir", "children": {}}

    for rec in file_records:
        parts = rec["path"].replace("\\", "/").split("/")
        node = root
        for i, part in enumerate(parts):
            if part not in node["children"]:
                is_file = i == len(parts) - 1
                node["children"][part] = {
                    "name": part,
                    "path": "/".join(parts[: i + 1]),
                    "type": "file" if is_file else "dir",
                    "children": {},
                }
                if is_file:
                    node["children"][part].update({
                        "id": rec["id"],
                        "language": rec.get("language"),
                        "size_bytes": rec.get("size_bytes"),
                    })
            node = node["children"][part]

    def _to_list(node: dict) -> list[dict]:
        children = sorted(
            node["children"].values(),
            key=lambda x: (0 if x["type"] == "dir" else 1, x["name"].lower()),
        )
        result = []
        for child in children:
            entry = {
                "name": child["name"],
                "path": child["path"],
                "type": child["type"],
            }
            if child["type"] == "file":
                entry["id"] = child.get("id")
                entry["language"] = child.get("language")
                entry["size_bytes"] = child.get("size_bytes")
            else:
                entry["children"] = _to_list(child)
            result.append(entry)
        return result

    return _to_list(root)


@router.get("/files/tree")
async def get_file_tree(scan_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Return hierarchical file tree for the scanned codebase."""
    result = await db.execute(
        select(File)
        .where(File.scan_id == scan_id)
        .order_by(File.path)
    )
    files = result.scalars().all()
    if not files:
        raise HTTPException(404, "No files found for this scan")

    records = [
        {
            "id": str(f.id),
            "path": f.path,
            "language": f.language,
            "size_bytes": f.size_bytes,
        }
        for f in files
    ]

    return {"tree": _build_tree(records), "total_files": len(records)}


@router.get("/files/{file_id}/content")
async def get_file_content(
    scan_id: uuid.UUID,
    file_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Return the content of a specific file from the scanned codebase."""
    file_rec = await db.get(File, file_id)
    if not file_rec or file_rec.scan_id != scan_id:
        raise HTTPException(404, "File not found")

    # Get the project to find repo path
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    project = await db.get(Project, scan.project_id)
    if not project or not project.repo_path:
        raise HTTPException(404, "Project source not found")

    file_path = Path(project.repo_path) / file_rec.path
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(404, f"File not found on disk: {file_rec.path}")

    # Size check
    size = file_path.stat().st_size
    if size > MAX_FILE_SIZE:
        return {
            "path": file_rec.path,
            "language": file_rec.language,
            "line_count": file_rec.line_count,
            "content": f"[File too large to display: {size:,} bytes. Max: {MAX_FILE_SIZE:,} bytes]",
            "truncated": True,
        }

    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return {
            "path": file_rec.path,
            "language": file_rec.language,
            "content": f"[Unable to read file: {e}]",
            "truncated": True,
        }

    return {
        "path": file_rec.path,
        "language": file_rec.language,
        "line_count": file_rec.line_count,
        "content": content,
        "truncated": False,
    }
