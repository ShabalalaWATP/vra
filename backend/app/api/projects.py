import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analysis.paths import DEFAULT_SKIP_DIRS
from app.config import settings
from app.database import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.schemas.project import ProjectCreate, ProjectOut, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["projects"])

UPLOAD_SKIP_DIRS = {
    *(name.casefold() for name in DEFAULT_SKIP_DIRS),
    ".eggs",
    ".npm",
    ".pnpm-store",
    ".yarn",
    ".yarn-cache",
    "htmlcov",
    "jspm_packages",
    "site-packages",
}


@dataclass(frozen=True)
class UploadSaveResult:
    saved: int
    ignored: int


def _safe_upload_relative_path(filename: str) -> Path | None:
    """Return a safe relative path for a browser folder upload."""
    normalised = filename.replace("\\", "/").strip()
    if not normalised:
        return None

    rel = PurePosixPath(normalised)
    if rel.is_absolute():
        return None

    parts = [part for part in rel.parts if part not in ("", ".")]
    if not parts:
        return None
    if any(part == ".." or part.endswith(":") for part in parts):
        return None
    return Path(*parts)


def _is_ignored_upload_path(rel_path: Path) -> bool:
    """Return True when an uploaded file lives under generated/dependency dirs."""
    return any(part.casefold() in UPLOAD_SKIP_DIRS for part in rel_path.parts)


async def _save_uploaded_codebase_files(
    upload_dir: Path,
    files: list[UploadFile],
) -> UploadSaveResult:
    upload_root = upload_dir.resolve()
    saved = 0
    ignored = 0

    for f in files:
        if not f.filename:
            continue

        rel_path = _safe_upload_relative_path(f.filename)
        if rel_path is None:
            continue
        if _is_ignored_upload_path(rel_path):
            ignored += 1
            continue

        dest = (upload_root / rel_path).resolve()
        try:
            dest.relative_to(upload_root)
        except ValueError:
            continue

        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            content = await f.read()
            dest.write_bytes(content)
            saved += 1
        except Exception:
            continue

    return UploadSaveResult(saved=saved, ignored=ignored)


def _project_out(project: Project, *, scan_count: int = 0) -> ProjectOut:
    return ProjectOut(
        id=project.id,
        name=project.name,
        description=project.description,
        repo_path=project.repo_path,
        source_type=project.source_type,
        created_at=project.created_at,
        updated_at=project.updated_at,
        scan_count=scan_count,
    )


@router.get("", response_model=list[ProjectOut])
async def list_projects(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Project).order_by(Project.updated_at.desc()))
    projects = result.scalars().all()

    # Batch-load scan counts in one query (avoids N+1)
    project_ids = [p.id for p in projects]
    scan_counts: dict = {}
    if project_ids:
        count_rows = await db.execute(
            select(Scan.project_id, func.count())
            .where(Scan.project_id.in_(project_ids))
            .group_by(Scan.project_id)
        )
        scan_counts = {row[0]: row[1] for row in count_rows.all()}

    out = []
    for p in projects:
        out.append(_project_out(p, scan_count=scan_counts.get(p.id, 0)))
    return out


@router.post("", response_model=ProjectOut, status_code=201)
async def create_project(body: ProjectCreate, db: AsyncSession = Depends(get_db)):
    repo = Path(body.repo_path)
    if not repo.exists():
        raise HTTPException(400, f"Path does not exist: {body.repo_path}")
    if not repo.is_dir():
        raise HTTPException(400, f"Path is not a directory: {body.repo_path}")

    project = Project(name=body.name, description=body.description, repo_path=body.repo_path)
    db.add(project)
    await db.flush()
    return _project_out(project)


# ── Upload routes MUST come before /{project_id} routes ──


@router.post("/upload-folder", response_model=ProjectOut, status_code=201)
async def upload_folder(
    name: str = Form(...),
    files: list[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
):
    """Upload an entire folder of source files and create a project."""
    if not files:
        raise HTTPException(400, "No files uploaded")

    # Create a unique directory for this upload
    project_id = uuid.uuid4()
    upload_dir = settings.upload_dir / "codebases" / str(project_id)
    upload_dir.mkdir(parents=True, exist_ok=True)

    save_result = await _save_uploaded_codebase_files(upload_dir, files)

    if save_result.saved == 0:
        shutil.rmtree(upload_dir, ignore_errors=True)
        if save_result.ignored:
            raise HTTPException(
                400,
                "No valid source files were uploaded; dependency/generated folders "
                "such as node_modules are ignored.",
            )
        raise HTTPException(400, "No valid files were uploaded")

    # Find the actual root — if all files share a common prefix directory, use that
    subdirs = [d for d in upload_dir.iterdir() if d.is_dir()]
    repo_path = upload_dir
    if len(subdirs) == 1 and not any(upload_dir.glob("*.*")):
        repo_path = subdirs[0]  # Use the single subdirectory as root

    description = f"Uploaded {save_result.saved} files via browser"
    if save_result.ignored:
        description += f" (ignored {save_result.ignored} dependency/generated files)"

    project = Project(
        id=project_id,
        name=name or f"Upload {project_id}",
        repo_path=str(repo_path),
        source_type="codebase",
        description=description,
    )
    db.add(project)
    await db.flush()

    return _project_out(project)


@router.post("/upload-apk", response_model=ProjectOut, status_code=201)
async def upload_apk(file: UploadFile, db: AsyncSession = Depends(get_db)):
    """
    Upload an APK/AAB file, decompile it to Java source, and create a project.

    The APK is decompiled using jadx (must be installed). The decompiled source
    is stored on disk and a project is created pointing to it. The project can
    then be scanned like any other codebase.

    Supports: .apk, .aab, .dex, .jar
    """
    from app.analysis.apk_decompiler import decompile_apk, is_jadx_available

    if not file.filename:
        raise HTTPException(400, "No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".apk", ".aab", ".dex", ".jar"):
        raise HTTPException(
            400,
            f"Unsupported file type: {suffix}. Expected .apk, .aab, .dex, or .jar",
        )

    if not await is_jadx_available():
        raise HTTPException(
            503,
            "jadx is not installed. Install it to backend/tools/jadx/ "
            "or run: python -m scripts.download_jadx",
        )

    # Save uploaded file to disk
    upload_dir = settings.upload_dir / "apk"
    upload_dir.mkdir(parents=True, exist_ok=True)
    apk_path = upload_dir / f"{uuid.uuid4().hex}_{file.filename}"

    try:
        with open(apk_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        raise HTTPException(500, f"Failed to save uploaded file: {e}")

    # Decompile
    output_dir = settings.upload_dir / "decompiled" / apk_path.stem
    result = await decompile_apk(apk_path, output_dir=output_dir)

    if not result["success"]:
        # Clean up
        apk_path.unlink(missing_ok=True)
        raise HTTPException(
            500,
            f"APK decompilation failed: {'; '.join(result['errors'])}",
        )

    # Create project pointing to decompiled source
    source_dir = result["source_dir"]
    project_name = Path(file.filename).stem
    stats = result.get("stats", {})

    project = Project(
        name=f"{project_name} (APK)",
        description=(
            f"Decompiled from {file.filename}. "
            f"{stats.get('java_files', 0)} Java files, "
            f"{stats.get('xml_files', 0)} XML files. "
            f"jadx {result.get('jadx_version', 'unknown')}."
        ),
        repo_path=source_dir,
        source_type="apk" if suffix == ".apk" else suffix.lstrip("."),
    )
    db.add(project)
    await db.flush()

    return _project_out(project)


# ── Parameterized routes MUST come after literal path routes ──


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    count_result = await db.execute(
        select(func.count()).where(Scan.project_id == project.id)
    )
    return _project_out(project, scan_count=count_result.scalar() or 0)


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: uuid.UUID, body: ProjectUpdate, db: AsyncSession = Depends(get_db)
):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(project, field, value)
    await db.flush()
    count_result = await db.execute(
        select(func.count()).where(Scan.project_id == project.id)
    )
    return _project_out(project, scan_count=count_result.scalar() or 0)


@router.delete("/{project_id}", status_code=204)
async def delete_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    await db.delete(project)
