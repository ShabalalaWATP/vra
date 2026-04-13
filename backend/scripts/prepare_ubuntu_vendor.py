from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from scripts.bundle_python_scanners import PACKAGES as SCANNER_PACKAGES

MAX_GIT_BLOB_BYTES = 95 * 1024 * 1024
NODE_ARCHIVE_BASENAME = "node_modules.tar.gz"
SCANNERS_ARCHIVE_BASENAME = "python_vendor.tar.gz"
CODEQL_ARCHIVE_BASENAME = "codeql.tar.gz"
JADX_ARCHIVE_BASENAME = "jadx.tar.gz"


def log(message: str) -> None:
    print(f"[+] {message}")


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def run(cmd: list[str], *, cwd: Path, description: str) -> None:
    log(description)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def find_command(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise FileNotFoundError(f"{name} is required on PATH")
    return resolved


def ensure_clean_dir(path: Path, *, clean: bool) -> None:
    if clean and path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def build_python_wheelhouse(backend_dir: Path, wheelhouse: Path) -> None:
    ensure_clean_dir(wheelhouse, clean=True)
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "--dest",
        str(wheelhouse),
        "setuptools",
        "wheel",
        ".[dev]",
        *SCANNER_PACKAGES,
    ]
    run(cmd, cwd=backend_dir, description=f"Downloading Ubuntu wheelhouse into {wheelhouse}")


def ensure_frontend_modules(frontend_dir: Path) -> None:
    node_modules = frontend_dir / "node_modules"
    if node_modules.exists():
        log("Using existing frontend/node_modules")
        return

    npm = find_command("npm")
    install_args = ["ci"] if (frontend_dir / "package-lock.json").exists() else ["install"]
    run([npm, *install_args], cwd=frontend_dir, description="Installing frontend dependencies")


def archive_node_modules(frontend_dir: Path, archive_path: Path) -> None:
    node_modules = frontend_dir / "node_modules"
    if not node_modules.exists():
        raise FileNotFoundError(f"Missing node_modules at {node_modules}")

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.exists():
        archive_path.unlink()

    log(f"Packing frontend/node_modules into {archive_path}")
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(node_modules, arcname="node_modules")


def remove_split_archive_parts(archive_path: Path) -> None:
    for part in archive_path.parent.glob(f"{archive_path.name}.part-*"):
        part.unlink()


def remove_archive_and_parts(archive_path: Path) -> None:
    if archive_path.exists():
        archive_path.unlink()
    remove_split_archive_parts(archive_path)


def split_archive_if_needed(archive_path: Path) -> list[Path]:
    if not archive_path.exists():
        return []

    size = archive_path.stat().st_size
    if size <= MAX_GIT_BLOB_BYTES:
        remove_split_archive_parts(archive_path)
        return [archive_path]

    parts: list[Path] = []
    remove_split_archive_parts(archive_path)
    log(
        f"Archive {archive_path.name} is {size / 1024 / 1024:.1f} MB; "
        f"splitting into <= {MAX_GIT_BLOB_BYTES / 1024 / 1024:.0f} MB parts for Git compatibility"
    )
    with archive_path.open("rb") as src:
        index = 0
        while True:
            chunk = src.read(MAX_GIT_BLOB_BYTES)
            if not chunk:
                break
            part_path = archive_path.parent / f"{archive_path.name}.part-{index:03d}"
            part_path.write_bytes(chunk)
            parts.append(part_path)
            index += 1

    archive_path.unlink()
    return parts


def archive_directory(source_dir: Path, archive_path: Path) -> list[Path]:
    if not source_dir.exists():
        remove_archive_and_parts(archive_path)
        return []

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    remove_archive_and_parts(archive_path)
    log(f"Packing {source_dir.name} into {archive_path}")
    with tarfile.open(archive_path, "w:gz") as archive:
        archive.add(source_dir, arcname=source_dir.name)
    shutil.rmtree(source_dir)
    return split_archive_if_needed(archive_path)


def stage_tool(
    *,
    backend_dir: Path,
    output_dir: Path,
    module_name: str,
    description: str,
) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    run(
        [sys.executable, "-m", module_name, "--output", str(output_dir)],
        cwd=backend_dir,
        description=description,
    )


def stage_python_scanners(*, backend_dir: Path, output_dir: Path, wheelhouse: Path) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    run(
        [
            sys.executable,
            "-m",
            "scripts.bundle_python_scanners",
            "--output-dir",
            str(output_dir),
            "--no-index",
            "--wheelhouse",
            str(wheelhouse),
        ],
        cwd=backend_dir,
        description=f"Bundling project-local Python scanners into {output_dir}",
    )


def write_manifest(
    manifest_path: Path,
    *,
    wheelhouse: Path,
    scanner_archives: list[Path],
    node_archives: list[Path],
    codeql_archives: list[Path],
    jadx_archives: list[Path],
) -> None:
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "prepared_on": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "intended_target": "Ubuntu/Linux host with the same CPU architecture",
        "included": {
            "python_wheels": len(list(wheelhouse.iterdir())) if wheelhouse.exists() else 0,
            "python_scanners": bool(scanner_archives),
            "python_scanners_archive_parts": [path.name for path in scanner_archives],
            "node_modules_archive": bool(node_archives),
            "node_modules_archive_parts": [path.name for path in node_archives],
            "codeql": bool(codeql_archives),
            "codeql_archive_parts": [path.name for path in codeql_archives],
            "jadx": bool(jadx_archives),
            "jadx_archive_parts": [path.name for path in jadx_archives],
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare vendored Ubuntu assets that can be committed and cloned with the repo.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("..") / "vendor" / "ubuntu",
        help="Vendor root relative to backend/ (default: ../vendor/ubuntu)",
    )
    parser.add_argument(
        "--include-node-modules",
        action="store_true",
        help="Include a node_modules.tar.gz archive for clone-only frontend tooling bootstraps.",
    )
    parser.add_argument(
        "--skip-codeql",
        action="store_true",
        help="Do not vendor CodeQL.",
    )
    parser.add_argument(
        "--skip-jadx",
        action="store_true",
        help="Do not vendor jadx.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if platform.system() != "Linux":
        warn("This script is intended to be run on a connected Ubuntu/Linux machine.")
        warn(f"Current platform: {platform.system()} {platform.machine()}")
        return 1

    repo_root = Path(__file__).resolve().parents[2]
    backend_dir = repo_root / "backend"
    frontend_dir = repo_root / "frontend"
    vendor_root = (backend_dir / args.output_root).resolve()

    if not str(vendor_root).startswith(str(repo_root.resolve())):
        warn(f"Refusing to write outside the repo: {vendor_root}")
        return 1

    vendor_python = vendor_root / "python"
    vendor_tools = vendor_root / "tools"
    vendor_scanners = vendor_tools / "python_vendor"
    vendor_scanners_archive = vendor_tools / SCANNERS_ARCHIVE_BASENAME
    vendor_codeql = vendor_tools / "codeql"
    vendor_codeql_archive = vendor_tools / CODEQL_ARCHIVE_BASENAME
    vendor_jadx = vendor_tools / "jadx"
    vendor_jadx_archive = vendor_tools / JADX_ARCHIVE_BASENAME
    vendor_node = vendor_root / NODE_ARCHIVE_BASENAME

    vendor_root.mkdir(parents=True, exist_ok=True)
    vendor_tools.mkdir(parents=True, exist_ok=True)

    build_python_wheelhouse(backend_dir, vendor_python)
    stage_python_scanners(
        backend_dir=backend_dir,
        output_dir=vendor_scanners,
        wheelhouse=vendor_python,
    )
    scanner_archives = archive_directory(vendor_scanners, vendor_scanners_archive)

    if args.include_node_modules:
        ensure_frontend_modules(frontend_dir)
        archive_node_modules(frontend_dir, vendor_node)
        node_archives = split_archive_if_needed(vendor_node)
    elif vendor_node.exists():
        vendor_node.unlink()
        remove_split_archive_parts(vendor_node)
        node_archives = []
    else:
        remove_split_archive_parts(vendor_node)
        node_archives = []

    if args.skip_codeql:
        warn("Skipping CodeQL vendoring")
        if vendor_codeql.exists():
            shutil.rmtree(vendor_codeql)
        remove_archive_and_parts(vendor_codeql_archive)
        codeql_archives = []
    else:
        stage_tool(
            backend_dir=backend_dir,
            output_dir=vendor_codeql,
            module_name="scripts.download_codeql",
            description=f"Downloading Ubuntu CodeQL bundle into {vendor_codeql}",
        )
        codeql_archives = archive_directory(vendor_codeql, vendor_codeql_archive)

    if args.skip_jadx:
        warn("Skipping jadx vendoring")
        if vendor_jadx.exists():
            shutil.rmtree(vendor_jadx)
        remove_archive_and_parts(vendor_jadx_archive)
        jadx_archives = []
    else:
        stage_tool(
            backend_dir=backend_dir,
            output_dir=vendor_jadx,
            module_name="scripts.download_jadx",
            description=f"Downloading jadx into {vendor_jadx}",
        )
        jadx_archives = archive_directory(vendor_jadx, vendor_jadx_archive)

    write_manifest(
        vendor_root / "manifest.json",
        wheelhouse=vendor_python,
        scanner_archives=scanner_archives,
        node_archives=node_archives,
        codeql_archives=codeql_archives,
        jadx_archives=jadx_archives,
    )

    log(f"Ubuntu vendor tree prepared at {vendor_root}")
    log("Commit vendor/ubuntu/ if you want plain git clone on Ubuntu to carry these assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
