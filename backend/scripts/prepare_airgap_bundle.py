from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SKIP_NAMES = {
    ".DS_Store",
    "Thumbs.db",
}

SKIP_PARTS = {
    ".claude",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "venv",
}

SKIP_PREFIXES = (
    "backend/exports",
    "backend/tools/codeql",
    "backend/tools/jadx",
    "backend/tools/python_vendor",
    "backend/uploads",
    "frontend/node_modules",
    "offline-packages",
    "vendor/ubuntu",
)


def log(message: str) -> None:
    print(f"[+] {message}")


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def run(cmd: list[str], *, cwd: Path, description: str) -> None:
    log(description)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def find_command(name: str) -> str:
    candidates = [name]
    if os.name == "nt":
        candidates = [f"{name}.cmd", f"{name}.exe", name]
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise FileNotFoundError(f"{name} is required on PATH")


def build_python_wheelhouse(backend_dir: Path, wheelhouse: Path) -> None:
    wheelhouse.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--dest",
        str(wheelhouse),
        "setuptools",
        "wheel",
        "semgrep",
        "bandit",
        ".[dev]",
    ]
    run(cmd, cwd=backend_dir, description=f"Downloading Python wheels into {wheelhouse}")


def ensure_frontend_modules(frontend_dir: Path) -> None:
    node_modules = frontend_dir / "node_modules"
    if node_modules.exists():
        log("Using existing frontend/node_modules")
        return

    npm = find_command("npm")
    install_args = ["ci"] if (frontend_dir / "package-lock.json").exists() else ["install"]
    run([npm, *install_args], cwd=frontend_dir, description="Installing frontend dependencies")


def build_frontend_dist(frontend_dir: Path) -> None:
    npm = find_command("npm")
    run([npm, "run", "build"], cwd=frontend_dir, description="Building frontend/dist")


def create_node_modules_archive(frontend_dir: Path, target: Path) -> None:
    node_modules = frontend_dir / "node_modules"
    if not node_modules.exists():
        raise FileNotFoundError(f"Missing node_modules at {node_modules}")

    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()

    log(f"Packing frontend/node_modules into {target}")
    with tarfile.open(target, "w:gz") as archive:
        archive.add(node_modules, arcname="node_modules")


def tool_binary_candidates(tool_name: str, tool_dir: Path) -> list[Path]:
    if tool_name == "codeql":
        return [tool_dir / "codeql.exe", tool_dir / "codeql"]
    if tool_name == "jadx":
        return [tool_dir / "bin" / "jadx.bat", tool_dir / "bin" / "jadx"]
    raise ValueError(f"Unsupported tool: {tool_name}")


def has_tool_binary(tool_name: str, tool_dir: Path) -> bool:
    return any(candidate.exists() for candidate in tool_binary_candidates(tool_name, tool_dir))


def stage_tool(
    *,
    tool_name: str,
    backend_dir: Path,
    staged_dir: Path,
    download_module: str,
    skip_download: bool,
) -> bool:
    local_dir = backend_dir / "tools" / tool_name
    if has_tool_binary(tool_name, local_dir):
        log(f"Using existing {tool_name} from {local_dir}")
        if staged_dir.exists():
            shutil.rmtree(staged_dir)
        shutil.copytree(local_dir, staged_dir)
        return True

    if skip_download:
        warn(f"Skipping {tool_name}; no local copy found.")
        return False

    staged_dir.mkdir(parents=True, exist_ok=True)
    run(
        [sys.executable, "-m", download_module, "--output", str(staged_dir)],
        cwd=backend_dir,
        description=f"Downloading {tool_name} into the bundle staging area",
    )
    return has_tool_binary(tool_name, staged_dir)


def stage_python_scanners(*, backend_dir: Path, staged_dir: Path) -> bool:
    if staged_dir.exists():
        shutil.rmtree(staged_dir)
    run(
        [
            sys.executable,
            "-m",
            "scripts.bundle_python_scanners",
            "--output-dir",
            str(staged_dir),
        ],
        cwd=backend_dir,
        description=f"Bundling project-local Python scanners into {staged_dir}",
    )
    return (staged_dir / "semgrep").exists() and (staged_dir / "bandit").exists()


def write_manifest(
    *,
    manifest_path: Path,
    wheelhouse: Path,
    node_archive: Path,
    python_scanners_included: bool,
    codeql_included: bool,
    jadx_included: bool,
    build_frontend: bool,
) -> None:
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "prepared_on": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "notes": [
            "Prepare the bundle on the same OS and CPU architecture as the target air-gapped machine.",
            "Do not commit the generated tarball into Git history; publish it as a release artifact or transfer it out-of-band.",
        ],
        "included": {
            "python_packages": len(list(wheelhouse.iterdir())) if wheelhouse.exists() else 0,
            "node_modules_archive": node_archive.exists(),
            "python_scanners": python_scanners_included,
            "codeql": codeql_included,
            "jadx": jadx_included,
            "frontend_dist_rebuilt": build_frontend,
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def should_skip_repo_path(path: Path, repo_root: Path, output_path: Path) -> bool:
    rel = path.relative_to(repo_root)
    rel_posix = rel.as_posix()

    if rel_posix == ".":
        return False

    if output_path.is_relative_to(repo_root) and path == output_path:
        return True

    if any(part in SKIP_PARTS for part in rel.parts):
        return True

    if path.name in SKIP_NAMES:
        return True

    if any(rel_posix == prefix or rel_posix.startswith(prefix + "/") for prefix in SKIP_PREFIXES):
        return True

    if path.is_file() and path.suffix.lower() in {".pyc", ".pyo", ".db", ".sqlite3"}:
        return True

    return False


def add_directory(
    archive: tarfile.TarFile,
    *,
    source_root: Path,
    archive_root: Path,
    path_filter,
) -> None:
    archive.add(source_root, arcname=archive_root.as_posix(), recursive=False)

    for current_dir, dirnames, filenames in os.walk(source_root):
        current_path = Path(current_dir)
        dirnames[:] = sorted(
            name for name in dirnames if not path_filter(current_path / name)
        )
        rel_dir = current_path.relative_to(source_root)

        if rel_dir != Path("."):
            archive.add(
                current_path,
                arcname=(archive_root / rel_dir).as_posix(),
                recursive=False,
            )

        for filename in sorted(filenames):
            file_path = current_path / filename
            if path_filter(file_path):
                continue
            archive.add(
                file_path,
                arcname=(archive_root / rel_dir / filename).as_posix(),
                recursive=False,
            )


def create_bundle_archive(
    *,
    repo_root: Path,
    offline_root: Path,
    output_path: Path,
) -> None:
    archive_root = Path(repo_root.name)
    if output_path.exists():
        output_path.unlink()

    log(f"Creating bundle archive at {output_path}")
    with tarfile.open(output_path, "w:gz") as archive:
        add_directory(
            archive,
            source_root=repo_root,
            archive_root=archive_root,
            path_filter=lambda path: should_skip_repo_path(path, repo_root, output_path),
        )
        add_directory(
            archive,
            source_root=offline_root,
            archive_root=archive_root / "offline-packages",
            path_filter=lambda _path: False,
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a single-file air-gap bundle for VRAgent.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("..") / "vragent-airgap-bundle.tar.gz",
        help="Path to the generated tar.gz archive.",
    )
    parser.add_argument(
        "--skip-codeql",
        action="store_true",
        help="Do not include CodeQL in the bundle.",
    )
    parser.add_argument(
        "--skip-jadx",
        action="store_true",
        help="Do not include jadx in the bundle.",
    )
    parser.add_argument(
        "--skip-frontend-build",
        action="store_true",
        help="Reuse the existing frontend/dist instead of rebuilding it.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    backend_dir = repo_root / "backend"
    frontend_dir = repo_root / "frontend"
    output_path = (backend_dir / args.output).resolve()

    with tempfile.TemporaryDirectory(prefix="vragent-airgap-") as temp_dir:
        offline_root = Path(temp_dir) / "offline-packages"
        python_root = offline_root / "python"
        node_archive = offline_root / "node_modules.tar.gz"
        tools_root = offline_root / "tools"

        build_python_wheelhouse(backend_dir, python_root)
        python_scanners_included = stage_python_scanners(
            backend_dir=backend_dir,
            staged_dir=tools_root / "python_vendor",
        )
        ensure_frontend_modules(frontend_dir)
        if not args.skip_frontend_build:
            build_frontend_dist(frontend_dir)
        create_node_modules_archive(frontend_dir, node_archive)

        codeql_included = stage_tool(
            tool_name="codeql",
            backend_dir=backend_dir,
            staged_dir=tools_root / "codeql",
            download_module="scripts.download_codeql",
            skip_download=args.skip_codeql,
        )
        jadx_included = stage_tool(
            tool_name="jadx",
            backend_dir=backend_dir,
            staged_dir=tools_root / "jadx",
            download_module="scripts.download_jadx",
            skip_download=args.skip_jadx,
        )

        write_manifest(
            manifest_path=offline_root / "manifest.json",
            wheelhouse=python_root,
            node_archive=node_archive,
            python_scanners_included=python_scanners_included,
            codeql_included=codeql_included,
            jadx_included=jadx_included,
            build_frontend=not args.skip_frontend_build,
        )

        create_bundle_archive(
            repo_root=repo_root,
            offline_root=offline_root,
            output_path=output_path,
        )

    log(f"Air-gap bundle ready: {output_path}")
    log("Keep the tarball out of Git history. Publish it as a release artifact or transfer it separately.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
