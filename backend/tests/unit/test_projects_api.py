import uuid
from datetime import datetime
from io import BytesIO

import pytest
from fastapi import HTTPException, UploadFile

from app.api.projects import _project_out, _save_uploaded_codebase_files, upload_folder
from app.models.project import Project


def _upload(filename: str, content: bytes = b"content") -> UploadFile:
    return UploadFile(BytesIO(content), filename=filename)


def test_project_out_preserves_non_codebase_source_type():
    project = Project(
        id=uuid.uuid4(),
        name="Sample APK",
        description="decompiled app",
        repo_path="C:/tmp/decompiled-app",
        source_type="apk",
    )
    project.created_at = datetime(2026, 3, 22, 10, 0, 0)
    project.updated_at = datetime(2026, 3, 22, 10, 5, 0)

    out = _project_out(project, scan_count=3)

    assert out.source_type == "apk"
    assert out.scan_count == 3
    assert out.repo_path == "C:/tmp/decompiled-app"


@pytest.mark.asyncio
async def test_save_uploaded_codebase_files_skips_dependency_dirs(tmp_path):
    upload_dir = tmp_path / "uploads"
    upload_dir.mkdir()

    result = await _save_uploaded_codebase_files(
        upload_dir,
        [
            _upload("demo/node_modules/lodash/index.js", b"ignored"),
            _upload("demo/.git/config", b"ignored"),
            _upload("demo/src/app.js", b"kept"),
        ],
    )

    assert result.saved == 1
    assert result.ignored == 2
    assert (upload_dir / "demo" / "src" / "app.js").read_bytes() == b"kept"
    assert not (upload_dir / "demo" / "node_modules").exists()
    assert not (upload_dir / "demo" / ".git").exists()


@pytest.mark.asyncio
async def test_upload_folder_rejects_only_ignored_dependency_files(tmp_path, monkeypatch):
    monkeypatch.setattr("app.api.projects.settings.upload_dir", tmp_path / "uploads")

    with pytest.raises(HTTPException) as exc:
        await upload_folder(
            name="deps-only",
            files=[_upload("demo/node_modules/lodash/index.js")],
            db=None,
        )

    assert exc.value.status_code == 400
    assert "node_modules" in exc.value.detail
    codebases_dir = tmp_path / "uploads" / "codebases"
    assert not codebases_dir.exists() or not any(codebases_dir.iterdir())
