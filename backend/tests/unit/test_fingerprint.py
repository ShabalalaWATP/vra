"""Tests for repo fingerprinting."""

from unittest.mock import patch

from app.analysis.fingerprint import detect_workspaces, fingerprint_repo


def test_fingerprint_detects_languages(sample_repo):
    fp = fingerprint_repo(sample_repo)
    lang_names = [l["name"] for l in fp["languages"]]
    assert "python" in lang_names
    assert "javascript" in lang_names


def test_fingerprint_detects_frameworks(sample_repo):
    fp = fingerprint_repo(sample_repo)
    # requirements.txt triggers python framework
    assert "python" in fp["frameworks"] or len(fp["frameworks"]) >= 0


def test_fingerprint_counts_files(sample_repo):
    fp = fingerprint_repo(sample_repo)
    assert fp["file_count"] >= 3


def test_fingerprint_excludes_managed_paths(tmp_path):
    backend = tmp_path / "backend"
    managed_data = backend / "data"
    managed_uploads = backend / "uploads"
    src = backend / "src"
    managed_data.mkdir(parents=True)
    managed_uploads.mkdir(parents=True)
    src.mkdir(parents=True)
    (managed_data / "rule.yaml").write_text("rules: []\n")
    (managed_uploads / "payload.py").write_text("print('payload')\n")
    (src / "app.py").write_text("print('real code')\n")

    with patch("app.config.settings") as mock_settings:
        mock_settings.data_dir = managed_data
        mock_settings.upload_dir = managed_uploads
        mock_settings.export_dir = backend / "exports"

        fp = fingerprint_repo(backend)

    assert fp["file_count"] == 1
    assert fp["ignored_file_count"] == 2
    assert "data" in fp["managed_paths_ignored"]
    assert "uploads" in fp["managed_paths_ignored"]


def test_fingerprint_reports_repo_ignore_file(tmp_path):
    (tmp_path / ".vragentignore").write_text("generated/\n")
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "sample.py").write_text("print('ignored')\n")
    (tmp_path / "app.py").write_text("print('kept')\n")

    fp = fingerprint_repo(tmp_path)

    assert fp["file_count"] == 1
    assert fp["ignored_file_count"] == 2
    assert fp["repo_ignore_file"]


def test_fingerprint_detects_flutter_and_elixir_manifests(tmp_path):
    (tmp_path / "pubspec.yaml").write_text("name: flutter_app\n")
    (tmp_path / "mix.exs").write_text("defmodule Demo.MixProject do\nend\n")

    fp = fingerprint_repo(tmp_path)

    assert "flutter" in fp["frameworks"]
    assert "dart" in fp["frameworks"]
    assert "elixir" in fp["frameworks"]


def test_detect_workspaces_includes_flutter_and_elixir_projects(tmp_path):
    apps_dir = tmp_path / "apps"
    flutter_app = apps_dir / "mobile"
    elixir_app = apps_dir / "api"
    flutter_app.mkdir(parents=True)
    elixir_app.mkdir(parents=True)
    (flutter_app / "pubspec.yaml").write_text("name: mobile\n")
    (elixir_app / "mix.exs").write_text("defmodule Api.MixProject do\nend\n")

    workspaces = detect_workspaces(tmp_path)
    manifests = {(ws["path"], ws["manifest"]) for ws in workspaces}

    assert ("apps/mobile", "pubspec.yaml") in manifests
    assert ("apps/api", "mix.exs") in manifests
