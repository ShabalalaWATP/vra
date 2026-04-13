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
        "semgrep",
        "bandit",
        ".[dev]",
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
    scanner_dir: Path,
    node_archive: Path | None,
    codeql_dir: Path,
    jadx_dir: Path,
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
            "python_scanners": scanner_dir.exists(),
            "node_modules_archive": bool(node_archive and node_archive.exists()),
            "codeql": codeql_dir.exists(),
            "jadx": jadx_dir.exists(),
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
    vendor_codeql = vendor_tools / "codeql"
    vendor_jadx = vendor_tools / "jadx"
    vendor_node = vendor_root / "node_modules.tar.gz"

    vendor_root.mkdir(parents=True, exist_ok=True)
    vendor_tools.mkdir(parents=True, exist_ok=True)

    build_python_wheelhouse(backend_dir, vendor_python)
    stage_python_scanners(
        backend_dir=backend_dir,
        output_dir=vendor_scanners,
        wheelhouse=vendor_python,
    )

    if args.include_node_modules:
        ensure_frontend_modules(frontend_dir)
        archive_node_modules(frontend_dir, vendor_node)
    elif vendor_node.exists():
        vendor_node.unlink()

    if args.skip_codeql:
        warn("Skipping CodeQL vendoring")
    else:
        stage_tool(
            backend_dir=backend_dir,
            output_dir=vendor_codeql,
            module_name="scripts.download_codeql",
            description=f"Downloading Ubuntu CodeQL bundle into {vendor_codeql}",
        )

    if args.skip_jadx:
        warn("Skipping jadx vendoring")
    else:
        stage_tool(
            backend_dir=backend_dir,
            output_dir=vendor_jadx,
            module_name="scripts.download_jadx",
            description=f"Downloading jadx into {vendor_jadx}",
        )

    write_manifest(
        vendor_root / "manifest.json",
        wheelhouse=vendor_python,
        scanner_dir=vendor_scanners,
        node_archive=vendor_node if args.include_node_modules else None,
        codeql_dir=vendor_codeql,
        jadx_dir=vendor_jadx,
    )

    log(f"Ubuntu vendor tree prepared at {vendor_root}")
    log("Commit vendor/ubuntu/ if you want plain git clone on Ubuntu to carry these assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
