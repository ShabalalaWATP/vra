from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from scripts.bundle_python_scanners import PACKAGES as SCANNER_PACKAGES

MAX_GIT_BLOB_BYTES = 95 * 1024 * 1024
NODE_ARCHIVE_BASENAME = "node_modules.tar.gz"
SCANNERS_ARCHIVE_BASENAME = "python_vendor.tar.gz"
CODEQL_ARCHIVE_BASENAME = "codeql.tar.gz"
JADX_ARCHIVE_BASENAME = "jadx.tar.gz"
REQUIRED_PYTHON_MINOR = (3, 12)
MIN_NODE_MAJOR = 22
MIN_NPM_MAJOR = 10


def log(message: str) -> None:
    print(f"[+] {message}")


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr)


def run(cmd: list[str], *, cwd: Path, description: str) -> None:
    log(description)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def venv_python_path(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def run_download_module_with_wheelhouse(
    *,
    backend_dir: Path,
    wheelhouse: Path,
    module_name: str,
    module_args: list[str],
    description: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="vragent-tool-download-") as temp_dir:
        venv_dir = Path(temp_dir) / "venv"
        run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            cwd=backend_dir,
            description="Creating temporary downloader environment",
        )
        downloader_python = venv_python_path(venv_dir)
        run(
            [
                str(downloader_python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--find-links",
                str(wheelhouse),
                "httpx",
            ],
            cwd=backend_dir,
            description="Installing downloader dependencies from the prepared wheelhouse",
        )
        run(
            [str(downloader_python), "-m", module_name, *module_args],
            cwd=backend_dir,
            description=description,
        )


def output_or_none(cmd: list[str], *, cwd: Path) -> str | None:
    try:
        completed = subprocess.run(
            cmd,
            cwd=str(cwd),
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except Exception:
        return None
    return completed.stdout.strip().splitlines()[0] if completed.stdout.strip() else None


def find_command(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise FileNotFoundError(f"{name} is required on PATH")
    return resolved


def major_version(version: str | None) -> int | None:
    if not version:
        return None
    token = version.strip().splitlines()[0].removeprefix("v").split(".", 1)[0]
    return int(token) if token.isdigit() else None


def ensure_node_toolchain(frontend_dir: Path) -> str:
    node = find_command("node")
    npm = find_command("npm")
    node_version = output_or_none([node, "--version"], cwd=frontend_dir)
    npm_version = output_or_none([npm, "--version"], cwd=frontend_dir)
    node_major = major_version(node_version)
    npm_major = major_version(npm_version)
    if node_major is None or node_major < MIN_NODE_MAJOR:
        raise RuntimeError(
            f"Node.js {MIN_NODE_MAJOR}+ is required to prepare frontend dependencies; "
            f"found {node_version or 'unknown'}."
        )
    if npm_major is None or npm_major < MIN_NPM_MAJOR:
        raise RuntimeError(
            f"npm {MIN_NPM_MAJOR}+ is required to prepare frontend dependencies; "
            f"found {npm_version or 'unknown'}."
        )
    log(f"Using Node.js {node_version} and npm {npm_version}")
    return npm


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
    npm = ensure_node_toolchain(frontend_dir)
    node_modules = frontend_dir / "node_modules"
    if node_modules.exists():
        log("Removing existing frontend/node_modules so native optional packages match this Linux host")
        shutil.rmtree(node_modules)

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
    wheelhouse: Path,
    output_dir: Path,
    module_name: str,
    description: str,
) -> None:
    if output_dir.exists():
        shutil.rmtree(output_dir)
    run_download_module_with_wheelhouse(
        backend_dir=backend_dir,
        wheelhouse=wheelhouse,
        module_name=module_name,
        module_args=["--output", str(output_dir)],
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
    frontend_dir: Path,
    codeql_version: str | None,
    jadx_version: str | None,
) -> None:
    package_lock = frontend_dir / "package-lock.json"
    node_version = output_or_none(["node", "--version"], cwd=frontend_dir)
    npm_version = output_or_none(["npm", "--version"], cwd=frontend_dir)
    package_lock_version = None
    package_count = None
    if package_lock.exists():
        package_lock_data = json.loads(package_lock.read_text(encoding="utf-8"))
        package_lock_version = package_lock_data.get("lockfileVersion")
        package_count = len(package_lock_data.get("packages", {}))

    wheel_files = sorted(path.name for path in wheelhouse.iterdir()) if wheelhouse.exists() else []
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "prepared_on": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "required_target": {
            "os": "Ubuntu/Linux",
            "machine": platform.machine(),
            "python_minor": f"{REQUIRED_PYTHON_MINOR[0]}.{REQUIRED_PYTHON_MINOR[1]}",
            "same_cpu_architecture": True,
        },
        "versions": {
            "semgrep": "1.156.0",
            "bandit": "1.9.4",
            "codeql": codeql_version,
            "jadx": jadx_version,
            "node": node_version,
            "npm": npm_version,
            "package_lock_version": package_lock_version,
            "frontend_package_count": package_count,
            "tree_sitter": "0.20.4",
            "tree_sitter_languages": "1.10.2",
        },
        "included": {
            "python_wheels": len(list(wheelhouse.iterdir())) if wheelhouse.exists() else 0,
            "python_wheel_files": wheel_files,
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
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--skip-node-modules",
        action="store_true",
        help="Do not include node_modules.tar.gz; target install will need an internal npm mirror.",
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
    if sys.version_info[:2] != REQUIRED_PYTHON_MINOR:
        required = f"{REQUIRED_PYTHON_MINOR[0]}.{REQUIRED_PYTHON_MINOR[1]}"
        current = f"{sys.version_info.major}.{sys.version_info.minor}"
        warn(
            f"Python {required} is required to prepare the Ubuntu wheelhouse. "
            f"Current interpreter is Python {current}."
        )
        warn("Run from the repo root: bash ./prepare_ubuntu_vendor.sh")
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

    if not args.skip_node_modules:
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
        codeql_version = None
    else:
        stage_tool(
            backend_dir=backend_dir,
            wheelhouse=vendor_python,
            output_dir=vendor_codeql,
            module_name="scripts.download_codeql",
            description=f"Downloading Ubuntu CodeQL bundle into {vendor_codeql}",
        )
        codeql_version = output_or_none([str(vendor_codeql / "codeql"), "version", "--format=terse"], cwd=backend_dir)
        codeql_archives = archive_directory(vendor_codeql, vendor_codeql_archive)

    if args.skip_jadx:
        warn("Skipping jadx vendoring")
        if vendor_jadx.exists():
            shutil.rmtree(vendor_jadx)
        remove_archive_and_parts(vendor_jadx_archive)
        jadx_archives = []
        jadx_version = None
    else:
        stage_tool(
            backend_dir=backend_dir,
            wheelhouse=vendor_python,
            output_dir=vendor_jadx,
            module_name="scripts.download_jadx",
            description=f"Downloading jadx into {vendor_jadx}",
        )
        jadx_version = output_or_none([str(vendor_jadx / "bin" / "jadx"), "--version"], cwd=backend_dir)
        jadx_archives = archive_directory(vendor_jadx, vendor_jadx_archive)

    write_manifest(
        vendor_root / "manifest.json",
        wheelhouse=vendor_python,
        scanner_archives=scanner_archives,
        node_archives=node_archives,
        codeql_archives=codeql_archives,
        jadx_archives=jadx_archives,
        frontend_dir=frontend_dir,
        codeql_version=codeql_version,
        jadx_version=jadx_version,
    )

    log(f"Ubuntu vendor tree prepared at {vendor_root}")
    log("Commit vendor/ubuntu/ if you want plain git clone on Ubuntu to carry these assets.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
