"""Tests for cross-platform path utilities."""

from pathlib import Path

from app.analysis.paths import (
    normalise_path,
    is_safe_path,
    is_binary_extension,
    should_skip_dir,
    get_extension,
    relative_to_repo,
)


def test_normalise_path_backslashes():
    assert normalise_path("src\\auth\\login.py") == "src/auth/login.py"


def test_normalise_path_leading_dot_slash():
    assert normalise_path("./src/main.py") == "src/main.py"


def test_normalise_path_trailing_slash():
    assert normalise_path("src/auth/") == "src/auth"


def test_is_safe_path_normal(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").touch()
    assert is_safe_path("src/app.py", tmp_path)


def test_is_safe_path_traversal(tmp_path):
    assert not is_safe_path("../../etc/passwd", tmp_path)


def test_is_safe_path_absolute_escape(tmp_path):
    assert not is_safe_path("/etc/passwd", tmp_path)


def test_is_safe_path_sibling_prefix_escape(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    escape = tmp_path / "repo-escape"
    escape.mkdir()
    (escape / "secret.txt").write_text("secret")
    assert not is_safe_path("../repo-escape/secret.txt", repo)


def test_is_binary_extension():
    assert is_binary_extension("image.png")
    assert is_binary_extension("archive.zip")
    assert is_binary_extension("library.dll")
    assert not is_binary_extension("source.py")
    assert not is_binary_extension("config.json")


def test_should_skip_dir():
    assert should_skip_dir("node_modules")
    assert should_skip_dir(".git")
    assert should_skip_dir("__pycache__")
    assert not should_skip_dir("src")
    assert not should_skip_dir("app")


def test_get_extension():
    assert get_extension("main.py") == ".py"
    assert get_extension("Component.tsx") == ".tsx"
    assert get_extension("Makefile") == ""


def test_relative_to_repo():
    repo = Path("/home/user/project")
    file = Path("/home/user/project/src/auth/login.py")
    assert relative_to_repo(file, repo) == "src/auth/login.py"
