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

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ ships tomllib
    tomllib = None

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
}


def parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple.

    Handles standard semver (1.2.3), pre-release tags (1.0.0-beta.1),
    and non-standard versions (1.2.3.4).
    """
    # Strip leading 'v' or '=' prefix
    version_str = version_str.lstrip("v=").strip()
    # Split on hyphen to separate pre-release
    base, *pre = version_str.split("-", 1)
    parts = re.findall(r"\d+", base)
    nums = tuple(int(p) for p in parts)
    # Pre-release versions sort before their release (1.0.0-beta < 1.0.0)
    # Represent as: (1, 0, 0, 0) for pre-release, (1, 0, 0, 1) for release
    if pre:
        return nums + (0,)
    return nums + (1,)


def version_in_range(version: str, affected_range: str) -> bool:
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

    try:
        v = parse_version(version)

        # Handle tilde ranges: ~1.2.3 -> >=1.2.3, <1.3.0
        if affected_range.startswith("~"):
            base = affected_range[1:].strip()
            base_parts = re.findall(r"\d+", base)
            if len(base_parts) >= 2:
                upper = f"{base_parts[0]}.{int(base_parts[1]) + 1}.0"
                return v >= parse_version(base) and v < parse_version(upper)

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
                return v >= parse_version(base) and v < parse_version(upper)

        # Handle constraint-based ranges
        for constraint in affected_range.split(","):
            constraint = constraint.strip()
            if not constraint:
                continue

            if constraint.startswith("!="):
                if v == parse_version(constraint[2:]):
                    return False
            elif constraint.startswith(">="):
                if v < parse_version(constraint[2:]):
                    return False
            elif constraint.startswith(">"):
                if v <= parse_version(constraint[1:]):
                    return False
            elif constraint.startswith("<="):
                if v > parse_version(constraint[2:]):
                    return False
            elif constraint.startswith("<"):
                if v >= parse_version(constraint[1:]):
                    return False
            elif constraint.startswith("==") or constraint.startswith("="):
                eq_val = constraint.lstrip("=")
                if v != parse_version(eq_val):
                    return False
            else:
                # Bare version string = exact match
                if "." in constraint and v != parse_version(constraint):
                    return False

        return True
    except Exception:
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

        for advisory_file in db_path.glob("*.json"):
            try:
                data = json.loads(advisory_file.read_text())
                if not isinstance(data, list):
                    data = [data]

                for adv in data:
                    pkg_name = adv.get("package", "").lower()
                    if not pkg_name:
                        continue
                    if pkg_name not in index:
                        index[pkg_name] = []
                    index[pkg_name].append(adv)
            except Exception:
                continue

        self._index[ecosystem] = index
        self._loaded_ecosystems.add(ecosystem)

    def lookup_package(self, ecosystem: str, package: str, version: str) -> list[dict]:
        """Check a single package@version against advisories. Returns matching advisories."""
        self._load_ecosystem(ecosystem)
        pkg_index = self._index.get(ecosystem, {})
        advisories = pkg_index.get(package.lower(), [])

        matches = []
        for adv in advisories:
            affected = adv.get("affected_range", "")
            if not affected:
                continue
            if self._version_in_range(version, affected):
                aliases = adv.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                matches.append({
                    "cve_id": cve_id or adv.get("id", ""),
                    "severity": adv.get("severity", ""),
                    "summary": (adv.get("summary") or "")[:200],
                    "fixed_version": adv.get("fixed_version"),
                    "package": package,
                    "ecosystem": ecosystem,
                })
        return matches

    @staticmethod
    def _version_in_range(version: str, affected_range: str) -> bool:
        """Simple version range check. Handles common formats like >=0,<4.6.5."""
        try:
            from packaging.version import Version
            ver = Version(version)
            # Parse comma-separated constraints
            for constraint in affected_range.split(","):
                constraint = constraint.strip()
                if constraint.startswith(">="):
                    if ver < Version(constraint[2:]):
                        return False
                elif constraint.startswith(">"):
                    if ver <= Version(constraint[1:]):
                        return False
                elif constraint.startswith("<="):
                    if ver > Version(constraint[2:]):
                        return False
                elif constraint.startswith("<"):
                    if ver >= Version(constraint[1:]):
                        return False
                elif constraint.startswith("="):
                    if ver != Version(constraint[1:]):
                        return False
            return True
        except Exception:
            return False

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

        # Lookup is now O(1) per package instead of O(n) scanning all advisories
        for pkg in packages:
            ecosystem = pkg["ecosystem"]
            eco_index = self._index.get(ecosystem, {})
            pkg_advisories = eco_index.get(pkg["name"].lower(), [])

            for adv in pkg_advisories:
                affected = adv.get("affected_range", "")
                if version_in_range(pkg["version"], affected):
                    aliases = adv.get("aliases", [])
                    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)

                    hits.append(
                        ScannerHit(
                            rule_id=adv.get("id", "unknown"),
                            severity=adv.get("severity", "medium").lower(),
                            message=adv.get("summary", "Known vulnerability"),
                            file_path=pkg["source_file"],
                            start_line=0,
                            metadata={
                                "advisory_id": adv.get("id"),
                                "cve_id": cve_id,
                                "aliases": aliases,
                                "cvss": adv.get("cvss_score"),
                                "cvss_vector": adv.get("cvss_vector"),
                                "affected_range": affected,
                                "fixed_version": adv.get("fixed_version"),
                                "package": pkg["name"],
                                "ecosystem": ecosystem,
                                "installed_version": pkg["version"],
                                "cwes": adv.get("cwes", []),
                                "details": adv.get("details", "")[:500],
                                "references": adv.get("references", [])[:3],
                                "vulnerable_functions": adv.get("vulnerable_functions", []),
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

        for path in root.rglob("*"):
            if not path.is_file():
                continue

            rel_path = str(path.relative_to(root)).replace("\\", "/")
            if "node_modules" in rel_path:
                continue
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
                name.lower(),
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
