import uuid
from datetime import datetime

from app.api.projects import _project_out
from app.models.project import Project


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
