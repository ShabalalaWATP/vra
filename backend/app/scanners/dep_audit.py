"""Offline dependency advisory scanner.

Matches package versions from manifests/lockfiles against a local
advisory database in OSV JSON format.

Performance design:
- Advisories are indexed by (ecosystem, package_name) on load — O(1) lookup per package
- Only loads ecosystems that are actually needed for the detected packages
- Avoids loading the entire 250MB database into memory if only npm is needed
"""

import ast
import configparser
import json
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ ships tomllib
    tomllib = None

from app.analysis.advisory_db import load_ecosystem_advisories
from app.analysis.package_identity import (
    normalise_package_name,
    package_index_keys,
    package_lookup_keys,
)
from app.analysis.paths import load_repo_path_policy, should_skip_repo_path
from app.config import settings
from app.scanners.base import ScannerAdapter, ScannerHit, ScannerOutput

# Manifest file patterns and their ecosystems
MANIFEST_PATTERNS = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "package.json": "npm",
    "requirements.txt": "pypi",
    "Pipfile.lock": "pypi",
    "poetry.lock": "pypi",
    "setup.py": "pypi",
    "setup.cfg": "pypi",
    "Gemfile.lock": "rubygems",
    "go.sum": "go",
    "go.mod": "go",
    "Cargo.lock": "crates",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "*.csproj": "nuget",
    "packages.config": "nuget",
    "composer.lock": "packagist",
    "composer.json": "packagist",
    "pubspec.lock": "pub",
    "mix.lock": "hex",
}


QUALIFIER_REPLACEMENTS = {
    r"(?<=\d)[._-]?final\b": "",
    r"(?<=\d)[._-]?release\b": "",
    r"(?<=\d)[._-]?ga\b": "",
    r"(?<=\d)[._-]?preview\b": "rc",
    r"(?<=\d)[._-]?pre\b": "rc",
    r"(?<=\d)[._-]?cr\b": "rc",
    r"(?<=\d)[._-]?alpha\b": "a",
    r"(?<=\d)[._-]?beta\b": "b",
    r"(?<=\d)[._-]?snapshot\b": ".dev0",
}


def _normalise_version_token(version_str: str) -> str:
    value = str(version_str or "").strip().lstrip("=vV")
    if not value:
        return ""

    lowered = value.lower()
    for pattern, replacement in QUALIFIER_REPLACEMENTS.items():
        lowered = re.sub(pattern, replacement, lowered)

    lowered = re.sub(r"[._-]?(sp)(?=\d|$)", ".post", lowered)
    lowered = re.sub(r"[._-]?(dev)(?=\d|$)", ".dev", lowered)
    lowered = re.sub(r"\.+", ".", lowered).strip(".- _")
    return lowered


def _packaging_version(version_str: str) -> Version | None:
    normalised = _normalise_version_token(version_str)
    if not normalised:
        return None

    try:
        return Version(normalised)
    except InvalidVersion:
        return None


def parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple."""
    parsed = _packaging_version(version_str)
    if parsed is not None:
        return tuple(parsed.release) + (0 if parsed.is_prerelease else 1,)

    # Fallback for ecosystems with looser versioning (e.g. Maven qualifiers).
    version_str = _normalise_version_token(version_str)
    base, *pre = re.split(r"[-+]", version_str, maxsplit=1)
    parts = re.findall(r"\d+", base)
    nums = tuple(int(p) for p in parts)
    if pre:
        return nums + (0,)
    return nums + (1,)


def _compare_versions(left: str, right: str) -> int:
    left_version = _packaging_version(left)
    right_version = _packaging_version(right)
    if left_version is not None and right_version is not None:
        if left_version < right_version:
            return -1
        if left_version > right_version:
            return 1
        return 0

    left_key = parse_version(left)
    right_key = parse_version(right)
    if left_key < right_key:
        return -1
    if left_key > right_key:
        return 1
    return 0


def _pep440_in_range(version: str, affected_range: str) -> bool | None:
    if not version or not affected_range:
        return False
    if affected_range.startswith(("~", "^")):
        return None
    if "||" in affected_range:
        return any(_pep440_in_range(version, part.strip()) for part in affected_range.split("||"))

    version_obj = _packaging_version(version)
    if version_obj is None:
        return None

    affected_range = affected_range.strip()
    if affected_range == "*":
        return True

    if not re.match(r"^[<>=!~]", affected_range):
        candidate = _packaging_version(affected_range)
        if candidate is None:
            return None
        return version_obj == candidate

    try:
        specifiers = SpecifierSet(affected_range.replace(" ", ""))
    except InvalidSpecifier:
        return None
    return version_obj in specifiers


def version_in_range(version: str, affected_range: str, ecosystem: str | None = None) -> bool:
    """Check if a version falls within an affected range.

    Supports:
      - Comma-separated constraints: ">=1.0.0, <2.0.0"
      - Single version (exact match): "1.2.3"
      - OSV-style "introduced"/"fixed" encoded as ">=introduced, <fixed"
      - Wildcard: "*" (matches everything)
      - Tilde/caret: ~1.2 (>=1.2.0, <1.3.0), ^1.2.3 (>=1.2.3, <2.0.0)
    """
    if not version or not affected_range:
        return False

    affected_range = affected_range.strip()
    if affected_range == "*":
        return True

    ecosystem = (ecosystem or "").strip().lower()
    if ecosystem == "pypi":
        pep440_match = _pep440_in_range(version, affected_range)
        if pep440_match is not None:
            return pep440_match

    try:
        # Support OR-ed ranges produced when an advisory has multiple affected windows.
        if "||" in affected_range:
            return any(version_in_range(version, part.strip(), ecosystem) for part in affected_range.split("||"))

        # Handle tilde ranges: ~1.2.3 -> >=1.2.3, <1.3.0
        if affected_range.startswith("~"):
            base = affected_range[1:].strip()
            base_parts = re.findall(r"\d+", base)
            if len(base_parts) >= 2:
                upper = f"{base_parts[0]}.{int(base_parts[1]) + 1}.0"
                return _compare_versions(version, base) >= 0 and _compare_versions(version, upper) < 0

        # Handle caret ranges: ^1.2.3 -> >=1.2.3, <2.0.0
        if affected_range.startswith("^"):
            base = affected_range[1:].strip()
            base_parts = re.findall(r"\d+", base)
            if base_parts:
                major = int(base_parts[0])
                if major > 0:
                    upper = f"{major + 1}.0.0"
                elif len(base_parts) >= 2:
                    upper = f"0.{int(base_parts[1]) + 1}.0"
                else:
                    upper = "1.0.0"
                return _compare_versions(version, base) >= 0 and _compare_versions(version, upper) < 0

        # Handle constraint-based ranges
        for constraint in affected_range.split(","):
            constraint = constraint.strip()
            if not constraint:
                continue

            if constraint.startswith("!="):
                if _compare_versions(version, constraint[2:]) == 0:
                    return False
            elif constraint.startswith(">="):
                if _compare_versions(version, constraint[2:]) < 0:
                    return False
            elif constraint.startswith(">"):
                if _compare_versions(version, constraint[1:]) <= 0:
                    return False
            elif constraint.startswith("<="):
                if _compare_versions(version, constraint[2:]) > 0:
                    return False
            elif constraint.startswith("<"):
                if _compare_versions(version, constraint[1:]) >= 0:
                    return False
            elif constraint.startswith("==") or constraint.startswith("="):
                eq_val = constraint.lstrip("=")
                if _compare_versions(version, eq_val) != 0:
                    return False
            else:
                # Bare version string = exact match
                if "." in constraint and _compare_versions(version, constraint) != 0:
                    return False

        return True
    except Exception:
        return False


def version_matches_advisory(version: str, advisory: dict, ecosystem: str | None = None) -> bool:
    if not version or not advisory:
        return False

    affected_ranges = advisory.get("affected_ranges") or []
    for affected_range in affected_ranges:
        if isinstance(affected_range, str) and version_in_range(version, affected_range, ecosystem):
            return True

    affected_range = advisory.get("affected_range", "")
    if isinstance(affected_range, str) and affected_range and version_in_range(version, affected_range, ecosystem):
        return True

    affected_versions = advisory.get("affected_versions") or []
    if any(_compare_versions(version, str(candidate).strip()) == 0 for candidate in affected_versions if candidate):
        return True

    return False


class DepAuditAdapter(ScannerAdapter):
    """Offline dependency advisory matcher with indexed lookups."""

    def __init__(self):
        # Indexed by (ecosystem, package_name_lower) -> [advisory]
        self._index: dict[str, dict[str, list[dict]]] = {}
        self._loaded_ecosystems: set[str] = set()
        self._all_loaded = False

    @property
    def name(self) -> str:
        return "dep_audit"

    async def is_available(self) -> bool:
        return settings.advisory_db_path.exists()

    async def get_version(self) -> str | None:
        version_file = settings.advisory_db_path / "VERSION"
        if version_file.exists():
            return version_file.read_text().strip()
        return None

    def _load_advisories(self):
        """Compatibility helper for tests and eager-loading callers."""
        if self._all_loaded:
            return

        root = settings.advisory_db_path
        if not root.exists():
            self._all_loaded = True
            return

        for path in root.iterdir():
            if path.is_dir():
                self._load_ecosystem(path.name)

        self._all_loaded = True

    def _load_ecosystem(self, ecosystem: str):
        """Load and index advisories for a single ecosystem (lazy, on-demand)."""
        if ecosystem in self._loaded_ecosystems:
            return

        db_path = settings.advisory_db_path / ecosystem
        if not db_path.exists():
            self._loaded_ecosystems.add(ecosystem)
            return

        index: dict[str, list[dict]] = {}
        for adv in load_ecosystem_advisories(settings.advisory_db_path, ecosystem):
            pkg_name = adv.get("package", "")
            if not pkg_name:
                continue
            for key in package_index_keys(pkg_name, ecosystem):
                if key not in index:
                    index[key] = []
                index[key].append(adv)

        self._index[ecosystem] = index
        self._loaded_ecosystems.add(ecosystem)

    def lookup_package(self, ecosystem: str, package: str, version: str) -> list[dict]:
        """Check a single package@version against advisories. Returns matching advisories."""
        self._load_ecosystem(ecosystem)
        pkg_index = self._index.get(ecosystem, {})
        matched: dict[str, dict] = {}
        priority = {
            "exact_package_match": 3,
            "canonical_package_match": 2,
            "artifact_alias_match": 1,
        }

        for key, match_type in package_lookup_keys(package, ecosystem):
            for adv in pkg_index.get(key, []):
                if not version_matches_advisory(version, adv, ecosystem):
                    continue

                aliases = adv.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                advisory_id = adv.get("id", "")
                existing = matched.get(advisory_id)
                if existing and priority.get(existing["match_type"], 0) >= priority.get(match_type, 0):
                    continue

                matched[advisory_id] = {
                    "advisory_id": advisory_id,
                    "cve_id": cve_id or advisory_id,
                    "severity": adv.get("severity", ""),
                    "summary": (adv.get("summary") or "")[:200],
                    "fixed_version": adv.get("fixed_version"),
                    "vulnerable_functions": adv.get("vulnerable_functions", []),
                    "package": package,
                    "advisory_package": adv.get("package", ""),
                    "ecosystem": ecosystem,
                    "match_type": match_type,
                }
        return list(matched.values())

    async def run(
        self,
        target_path: Path,
        *,
        languages: list[str] | None = None,
        rules: list[str] | None = None,
        file_filter: list[str] | None = None,
    ) -> ScannerOutput:
        start = time.monotonic()

        # Discover packages first to know which ecosystems we need
        packages = self._discover_packages(target_path, file_filter=file_filter)
        hits = []

        # Group packages by ecosystem so we only load needed ecosystems
        ecosystems_needed = set(pkg["ecosystem"] for pkg in packages)
        for eco in ecosystems_needed:
            self._load_ecosystem(eco)

        # Lookup uses the pre-built alias index, keeping per-package work bounded.
        for pkg in packages:
            ecosystem = pkg["ecosystem"]
            matches = self.lookup_package(ecosystem, pkg["name"], pkg["version"])

            for match in matches:
                advisories = self._index.get(ecosystem, {})
                advisory = next(
                    (
                        adv
                        for adv in advisories.get(normalise_package_name(match["advisory_package"], ecosystem), [])
                        if adv.get("id") == match["advisory_id"]
                    ),
                    None,
                )
                if not advisory:
                    continue

                hits.append(
                    ScannerHit(
                        rule_id=advisory.get("id", "unknown"),
                        severity=advisory.get("severity", "medium").lower(),
                        message=advisory.get("summary", "Known vulnerability"),
                        file_path=pkg["source_file"],
                        start_line=0,
                        metadata={
                            "advisory_id": advisory.get("id"),
                            "cve_id": match["cve_id"],
                            "aliases": advisory.get("aliases", []),
                            "cvss": advisory.get("cvss_score"),
                            "cvss_vector": advisory.get("cvss_vector"),
                            "affected_range": advisory.get("affected_range", ""),
                            "affected_ranges": advisory.get("affected_ranges", []),
                            "affected_versions": advisory.get("affected_versions", []),
                            "fixed_version": advisory.get("fixed_version"),
                            "fixed_versions": advisory.get("fixed_versions", []),
                            "package": pkg["name"],
                            "matched_package": advisory.get("package", ""),
                            "ecosystem": ecosystem,
                            "installed_version": pkg["version"],
                            "cwes": advisory.get("cwes", []),
                            "details": advisory.get("details", "")[:500],
                            "references": advisory.get("references", [])[:3],
                            "vulnerable_functions": advisory.get("vulnerable_functions", []),
                            "match_type": match["match_type"],
                            "is_dev": pkg.get("is_dev", False),
                        },
                    )
                )

        duration = int((time.monotonic() - start) * 1000)
        return ScannerOutput(
            scanner_name=self.name,
            success=True,
            hits=hits,
            duration_ms=duration,
        )

    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        return await self.run(target_path, file_filter=files)

    def _discover_packages(self, root: Path, *, file_filter: list[str] | None = None) -> list[dict]:
        """Find manifest files and extract package info."""
        packages = []
        allowed = {
            str(Path(f)).replace("\\", "/").strip("/")
            for f in (file_filter or [])
        }
        policy = load_repo_path_policy(root)

        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if should_skip_repo_path(path, root, policy=policy):
                continue

            rel_path = str(path.relative_to(root)).replace("\\", "/")
            if allowed and rel_path not in allowed:
                continue

            parser = self._get_parser_for_path(path)
            if parser:
                packages.extend(parser(path, rel_path))

        deduped = []
        seen = set()
        for pkg in packages:
            name = (pkg.get("name") or "").strip()
            version = (pkg.get("version") or "").strip()
            ecosystem = (pkg.get("ecosystem") or "").strip()
            if not name or not version or not ecosystem:
                continue

            key = (
                ecosystem,
                normalise_package_name(name, ecosystem),
                version,
                pkg.get("source_file", ""),
                bool(pkg.get("is_dev", False)),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(pkg)

        return deduped

    def _get_parser_for_path(self, path: Path):
        name = path.name
        if name == "package.json":
            return self._parse_package_json
        if name == "package-lock.json":
            return self._parse_package_lock_json
        if name == "yarn.lock":
            return self._parse_yarn_lock
        if name == "pnpm-lock.yaml":
            return self._parse_pnpm_lock
        if name == "requirements.txt":
            return self._parse_requirements_txt
        if name == "Pipfile.lock":
            return self._parse_pipfile_lock
        if name == "poetry.lock":
            return self._parse_poetry_lock
        if name == "setup.py":
            return self._parse_setup_py
        if name == "setup.cfg":
            return self._parse_setup_cfg
        if name == "Cargo.lock":
            return self._parse_cargo_lock
        if name == "go.mod":
            return self._parse_go_mod
        if name == "go.sum":
            return self._parse_go_sum
        if name == "Gemfile.lock":
            return self._parse_gemfile_lock
        if name == "pom.xml":
            return self._parse_pom_xml
        if name == "build.gradle":
            return self._parse_build_gradle
        if path.suffix == ".csproj":
            return self._parse_csproj
        if name == "packages.config":
            return self._parse_packages_config
        if name == "composer.lock":
            return self._parse_composer_lock
        if name == "composer.json":
            return self._parse_composer_json
        if name == "pubspec.lock":
            return self._parse_pubspec_lock
        if name == "mix.lock":
            return self._parse_mix_lock
        return None

    @staticmethod
    def _clean_version(version: str | dict | None) -> str:
        if isinstance(version, dict):
            version = version.get("version") or version.get("resolved")
        if not isinstance(version, str):
            return ""

        cleaned = version.strip().strip("'\"")
        if not cleaned:
            return ""

        if cleaned.startswith(("workspace:", "file:", "link:", "git+", "github:", "path:")):
            return ""
        if cleaned.startswith("npm:"):
            cleaned = cleaned.split("npm:", 1)[1]
            if "@" in cleaned:
                cleaned = cleaned.rsplit("@", 1)[-1]

        cleaned = cleaned.split("||", 1)[0].strip()
        cleaned = re.sub(r"^[\^~<>=! ]+", "", cleaned)
        cleaned = cleaned.lstrip("v")
        return cleaned.strip()

    def _pkg(
        self,
        name: str,
        version: str | dict | None,
        ecosystem: str,
        rel_path: str,
        *,
        is_dev: bool = False,
    ) -> dict | None:
        clean_name = (name or "").strip()
        clean_version = self._clean_version(version)
        if not clean_name or not clean_version:
            return None
        return {
            "name": clean_name,
            "version": clean_version,
            "ecosystem": ecosystem,
            "source_file": rel_path,
            "is_dev": is_dev,
        }

    def _parse_package_json(self, path: Path, rel_path: str) -> list[dict]:
        try:
            data = json.loads(path.read_text())
            pkgs = []
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for name, version in data.get(section, {}).items():
                    pkg = self._pkg(
                        name,
                        version,
                        "npm",
                        rel_path,
                        is_dev=section == "devDependencies",
                    )
                    if pkg:
                        pkgs.append(pkg)
            return pkgs
        except Exception:
            return []

    def _parse_package_lock_json(self, path: Path, rel_path: str) -> list[dict]:
        try:
            data = json.loads(path.read_text())
        except Exception:
            return []

        pkgs = []
        packages = data.get("packages")
        if isinstance(packages, dict):
            for pkg_path, info in packages.items():
                if not pkg_path or "node_modules/" not in pkg_path:
                    continue
                name = info.get("name") or pkg_path.rsplit("node_modules/", 1)[-1]
                pkg = self._pkg(
                    name,
                    info.get("version"),
                    "npm",
                    rel_path,
                    is_dev=bool(info.get("dev", False)),
                )
                if pkg:
                    pkgs.append(pkg)
            return pkgs

        def walk_dependencies(deps: dict, *, inherited_dev: bool = False):
            for dep_name, dep_info in deps.items():
                if not isinstance(dep_info, dict):
                    continue
                is_dev = inherited_dev or bool(dep_info.get("dev", False))
                pkg = self._pkg(dep_name, dep_info.get("version"), "npm", rel_path, is_dev=is_dev)
                if pkg:
                    pkgs.append(pkg)
                nested = dep_info.get("dependencies", {})
                if isinstance(nested, dict):
                    walk_dependencies(nested, inherited_dev=is_dev)

        walk_dependencies(data.get("dependencies", {}))
        return pkgs

    def _parse_yarn_lock(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        current_names: list[str] = []

        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.rstrip()
                if not line:
                    continue

                if not raw_line.startswith((" ", "\t")) and line.endswith(":"):
                    selectors = [s.strip().strip('"').strip("'") for s in line[:-1].split(",")]
                    current_names = [s.rsplit("@", 1)[0] for s in selectors if "@" in s]
                    continue

                stripped = line.strip()
                if stripped.startswith("version "):
                    version = stripped.split(None, 1)[1].strip('"').strip("'")
                    for name in current_names:
                        pkg = self._pkg(name, version, "npm", rel_path)
                        if pkg:
                            pkgs.append(pkg)
                    current_names = []
        except Exception:
            return []

        return pkgs

    def _parse_pnpm_lock(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        package_key = re.compile(r"^\s{2,}/(.+):\s*$")

        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                match = package_key.match(line)
                if not match:
                    continue
                selector = match.group(1)
                if "@" not in selector:
                    continue
                name, version = selector.rsplit("@", 1)
                pkg = self._pkg(name, version, "npm", rel_path)
                if pkg:
                    pkgs.append(pkg)
        except Exception:
            return []

        return pkgs

    def _parse_pip_requirement(self, requirement: str, rel_path: str, *, is_dev: bool = False) -> dict | None:
        requirement = requirement.strip()
        if not requirement or requirement.startswith(("#", "-", ".", "git+")):
            return None

        requirement = requirement.split(";", 1)[0].strip()
        match = re.match(
            r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:===|==|~=|>=|<=|>|<)?\s*([A-Za-z0-9_.+-]+)?",
            requirement,
        )
        if not match or not match.group(2):
            return None

        return self._pkg(match.group(1), match.group(2), "pypi", rel_path, is_dev=is_dev)

    def _parse_requirements_txt(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        try:
            for line in path.read_text().splitlines():
                dep = self._parse_pip_requirement(line, rel_path)
                if dep:
                    pkgs.append(dep)
        except Exception:
            pass
        return pkgs

    def _parse_pipfile_lock(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        try:
            data = json.loads(path.read_text())
            for section in ("default", "develop"):
                for name, info in data.get(section, {}).items():
                    dep = self._pkg(
                        name,
                        info.get("version", "").lstrip("="),
                        "pypi",
                        rel_path,
                        is_dev=section == "develop",
                    )
                    if dep:
                        pkgs.append(dep)
        except Exception:
            return []
        return pkgs

    def _parse_poetry_lock(self, path: Path, rel_path: str) -> list[dict]:
        if tomllib is None:
            return []

        try:
            data = tomllib.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []

        pkgs = []
        for pkg in data.get("package", []):
            groups = pkg.get("groups") or []
            is_dev = pkg.get("category", "") == "dev" or "dev" in groups
            dep = self._pkg(
                pkg.get("name", ""),
                pkg.get("version", ""),
                "pypi",
                rel_path,
                is_dev=is_dev,
            )
            if dep:
                pkgs.append(dep)
        return pkgs

    def _parse_cargo_lock(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        try:
            content = path.read_text()
            current_name = None
            for line in content.splitlines():
                if line.startswith('name = "'):
                    current_name = line.split('"')[1]
                elif line.startswith('version = "') and current_name:
                    pkg = self._pkg(current_name, line.split('"')[1], "crates", rel_path)
                    if pkg:
                        pkgs.append(pkg)
                    current_name = None
        except Exception:
            pass
        return pkgs

    def _parse_go_mod(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        try:
            in_require = False
            for line in path.read_text().splitlines():
                line = line.strip()
                if line == "require (":
                    in_require = True
                    continue
                if line == ")":
                    in_require = False
                    continue
                if in_require and line:
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg = self._pkg(parts[0], parts[1].lstrip("v"), "go", rel_path)
                        if pkg:
                            pkgs.append(pkg)
        except Exception:
            pass
        return pkgs

    def _parse_go_sum(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        try:
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                module_name, version = parts[0], parts[1]
                if version.endswith("/go.mod"):
                    version = version[:-7]
                pkg = self._pkg(module_name, version.lstrip("v"), "go", rel_path)
                if pkg:
                    pkgs.append(pkg)
        except Exception:
            return []
        return pkgs

    def _parse_gemfile_lock(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        try:
            in_specs = False
            for line in path.read_text().splitlines():
                stripped = line.strip()
                if stripped == "specs:":
                    in_specs = True
                    continue
                if in_specs and stripped and not stripped.startswith("("):
                    # Lines like "    gem_name (1.2.3)"
                    match = re.match(r"(\S+)\s+\(([^)]+)\)", stripped)
                    if match:
                        pkg = self._pkg(match.group(1), match.group(2), "rubygems", rel_path)
                        if pkg:
                            pkgs.append(pkg)
                elif not line.startswith(" ") and in_specs:
                    in_specs = False
        except Exception:
            pass
        return pkgs

    def _parse_pom_xml(self, path: Path, rel_path: str) -> list[dict]:
        try:
            root = ET.parse(path).getroot()
        except Exception:
            return []

        pkgs = []
        for dep in root.findall(".//{*}dependency"):
            group_id = dep.findtext("{*}groupId", default="").strip()
            artifact_id = dep.findtext("{*}artifactId", default="").strip()
            version = dep.findtext("{*}version", default="").strip()
            scope = dep.findtext("{*}scope", default="").strip().lower()
            name = f"{group_id}:{artifact_id}" if group_id else artifact_id
            pkg = self._pkg(name, version, "maven", rel_path, is_dev=scope == "test")
            if pkg:
                pkgs.append(pkg)
        return pkgs

    def _parse_build_gradle(self, path: Path, rel_path: str) -> list[dict]:
        pattern = re.compile(
            r"^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation|classpath)"
            r"\s*(?:\(|\s)\s*['\"]([^:'\"]+):([^:'\"]+):([^'\"]+)['\"]",
            re.MULTILINE,
        )

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        pkgs = []
        for match in pattern.finditer(content):
            config = match.group(1)
            group_id = match.group(2)
            artifact_id = match.group(3)
            version = match.group(4)
            pkg = self._pkg(
                f"{group_id}:{artifact_id}",
                version,
                "maven",
                rel_path,
                is_dev="test" in config.lower(),
            )
            if pkg:
                pkgs.append(pkg)
        return pkgs

    def _parse_csproj(self, path: Path, rel_path: str) -> list[dict]:
        try:
            root = ET.parse(path).getroot()
        except Exception:
            return []

        pkgs = []
        for ref in root.findall(".//{*}PackageReference"):
            name = ref.attrib.get("Include") or ref.attrib.get("Update", "")
            version = ref.attrib.get("Version") or ref.findtext("{*}Version", default="")
            pkg = self._pkg(name, version, "nuget", rel_path)
            if pkg:
                pkgs.append(pkg)
        return pkgs

    def _parse_packages_config(self, path: Path, rel_path: str) -> list[dict]:
        try:
            root = ET.parse(path).getroot()
        except Exception:
            return []

        pkgs = []
        for pkg_node in root.findall(".//package"):
            pkg = self._pkg(
                pkg_node.attrib.get("id", ""),
                pkg_node.attrib.get("version", ""),
                "nuget",
                rel_path,
                is_dev=pkg_node.attrib.get("developmentDependency", "false").lower() == "true",
            )
            if pkg:
                pkgs.append(pkg)
        return pkgs

    def _parse_composer_lock(self, path: Path, rel_path: str) -> list[dict]:
        pkgs = []
        try:
            data = json.loads(path.read_text())
            for section in ("packages", "packages-dev"):
                for pkg in data.get(section, []):
                    dep = self._pkg(
                        pkg.get("name", ""),
                        pkg.get("version", "").lstrip("v"),
                        "packagist",
                        rel_path,
                        is_dev=section == "packages-dev",
                    )
                    if dep:
                        pkgs.append(dep)
        except Exception:
            pass
        return pkgs

    def _parse_composer_json(self, path: Path, rel_path: str) -> list[dict]:
        try:
            data = json.loads(path.read_text())
        except Exception:
            return []

        pkgs = []
        for section in ("require", "require-dev"):
            for name, version in data.get(section, {}).items():
                if name == "php" or name.startswith(("ext-", "lib-")):
                    continue
                pkg = self._pkg(
                    name,
                    version,
                    "packagist",
                    rel_path,
                    is_dev=section == "require-dev",
                )
                if pkg:
                    pkgs.append(pkg)
        return pkgs

    def _parse_pubspec_lock(self, path: Path, rel_path: str) -> list[dict]:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []

        packages = data.get("packages", {}) if isinstance(data, dict) else {}
        if not isinstance(packages, dict):
            return []

        pkgs = []
        for package_name, metadata in packages.items():
            if not isinstance(metadata, dict):
                continue

            source = str(metadata.get("source", "")).strip().lower()
            if source in {"path", "git"}:
                continue

            description = metadata.get("description")
            if isinstance(description, dict):
                package_name = description.get("name") or package_name

            dependency_type = str(metadata.get("dependency", "")).strip().lower()
            pkg = self._pkg(
                package_name,
                metadata.get("version"),
                "pub",
                rel_path,
                is_dev="dev" in dependency_type,
            )
            if pkg:
                pkgs.append(pkg)
        return pkgs

    def _parse_mix_lock(self, path: Path, rel_path: str) -> list[dict]:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        hex_entry_pattern = re.compile(
            r'"(?P<lock_name>[^"]+)"\s*(?:=>|:)\s*\{\s*:hex\s*,\s*'
            r'(?::"(?P<quoted_atom>[^"]+)"|:(?P<atom>[A-Za-z0-9_]+)|"(?P<quoted_name>[^"]+)")\s*,\s*'
            r'"(?P<version>[^"]+)"',
            re.MULTILINE,
        )

        pkgs = []
        for match in hex_entry_pattern.finditer(content):
            package_name = (
                match.group("quoted_atom")
                or match.group("atom")
                or match.group("quoted_name")
                or match.group("lock_name")
            )
            pkg = self._pkg(package_name, match.group("version"), "hex", rel_path)
            if pkg:
                pkgs.append(pkg)
        return pkgs

    def _parse_setup_py(self, path: Path, rel_path: str) -> list[dict]:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return []

        pkgs = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
            if func_name != "setup":
                continue

            for kw in node.keywords:
                if kw.arg == "install_requires" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    for elt in kw.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            dep = self._parse_pip_requirement(elt.value, rel_path)
                            if dep:
                                pkgs.append(dep)
                elif kw.arg == "extras_require" and isinstance(kw.value, ast.Dict):
                    for values in kw.value.values:
                        if isinstance(values, (ast.List, ast.Tuple)):
                            for elt in values.elts:
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                    dep = self._parse_pip_requirement(elt.value, rel_path, is_dev=True)
                                    if dep:
                                        pkgs.append(dep)

        return pkgs

    def _parse_setup_cfg(self, path: Path, rel_path: str) -> list[dict]:
        parser = configparser.ConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except Exception:
            return []

        pkgs = []
        install_requires = parser.get("options", "install_requires", fallback="")
        for line in install_requires.splitlines():
            dep = self._parse_pip_requirement(line, rel_path)
            if dep:
                pkgs.append(dep)

        if parser.has_section("options.extras_require"):
            for _, requirements in parser.items("options.extras_require"):
                for line in requirements.splitlines():
                    dep = self._parse_pip_requirement(line, rel_path, is_dev=True)
                    if dep:
                        pkgs.append(dep)

        return pkgs
