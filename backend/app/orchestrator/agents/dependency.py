"""Dependency Risk Agent — assess dependency vulnerabilities with AI context."""

import json
import logging
import re
from pathlib import Path

from sqlalchemy import select
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.11+ ships tomllib
    tomllib = None

from app.analysis.package_identity import (
    dependency_import_aliases,
    match_external_import_to_package,
    normalise_package_name,
)
from app.database import async_session
from app.models.dependency import Dependency, DependencyFinding
from app.models.file import File
from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import ScanContext

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a dependency security analyst. Your task is to assess whether
vulnerable dependencies are actually exploitable in this application's context.

For each vulnerable dependency, consider:
1. Is the package actually imported and used in the application code?
2. Is the vulnerable function/feature of the package used?
3. Is the vulnerability reachable given the application's architecture?
4. Is this a dev-only dependency that wouldn't be in production?
5. Are there mitigating factors (e.g., behind auth, internal only)?

Respond with JSON:
{
  "assessments": [
    {
      "package": "package-name",
      "advisory_id": "GHSA-...",
      "relevance": "used|likely_used|transitive_only|test_only|unknown",
      "reachability_status": "reachable|potentially_reachable|no_path_found|not_applicable",
      "assessment": "Brief explanation of why this dependency matters or doesn't",
      "risk_level": "critical|high|medium|low|info",
      "reasoning": "How you determined the relevance"
    }
  ]
}"""

ACTIVE_DEPENDENCY_RELEVANCE = {"used", "likely_used"}
LOCKFILE_NAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Pipfile.lock",
    "poetry.lock",
    "go.sum",
    "Cargo.lock",
    "Gemfile.lock",
    "composer.lock",
    "pubspec.lock",
    "mix.lock",
}


class DependencyRiskAgent(BaseAgent):
    def __init__(self, llm):
        super().__init__(llm)
        self._direct_dependency_cache: dict[tuple[str, str], bool | None] = {}

    @staticmethod
    def _dependency_usage_tokens(package: str, ecosystem: str) -> set[str]:
        package = (package or "").strip()
        if not package:
            return set()

        tokens = set(dependency_import_aliases(package, ecosystem))
        lowered = package.lower()
        tokens.update(
            {
                lowered,
                lowered.replace("-", "_"),
                lowered.replace(".", "/"),
            }
        )
        return {token for token in tokens if token}

    @staticmethod
    def _is_test_path(file_path: str) -> bool:
        path = file_path.replace("\\", "/").lower()
        parts = [part for part in path.split("/") if part]
        filename = parts[-1] if parts else path
        return (
            "test" in parts
            or "tests" in parts
            or "__tests__" in parts
            or filename.endswith((".test.js", ".test.ts", ".test.tsx", ".test.jsx"))
            or filename.endswith((".spec.js", ".spec.ts", ".spec.tsx", ".spec.jsx"))
            or filename.endswith(("_test.py", "_test.go", "_test.dart", "_spec.exs"))
            or filename.startswith("test_")
        )

    @staticmethod
    def _dedupe_usage_hits(usage_hits: list[dict]) -> list[dict]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict] = []
        for hit in usage_hits:
            key = (hit.get("file", ""), hit.get("kind", ""), hit.get("symbol", ""))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(hit)
        return deduped

    @staticmethod
    def _summarise_usage_hits(usage_hits: list[dict]) -> str:
        if not usage_hits:
            return "No usage evidence found"

        grouped: dict[str, list[str]] = {}
        for hit in usage_hits:
            grouped.setdefault(hit.get("kind", "reference"), []).append(hit.get("file", ""))

        parts = []
        for kind in ("import", "reference", "vulnerable_function"):
            files = grouped.get(kind, [])
            if not files:
                continue
            label = {
                "import": "imports",
                "reference": "references",
                "vulnerable_function": "vulnerable functions",
            }.get(kind, kind)
            parts.append(f"{label}: {', '.join(files[:3])}")
        return "; ".join(parts) if parts else "No usage evidence found"

    @staticmethod
    def _manifest_candidates(source_file: str) -> list[str]:
        source = Path(source_file or "")
        mapping = {
            "package-lock.json": ["package.json"],
            "yarn.lock": ["package.json"],
            "pnpm-lock.yaml": ["package.json"],
            "Pipfile.lock": ["Pipfile"],
            "poetry.lock": ["pyproject.toml"],
            "go.sum": ["go.mod"],
            "Cargo.lock": ["Cargo.toml"],
            "Gemfile.lock": ["Gemfile"],
            "composer.lock": ["composer.json"],
            "pubspec.lock": ["pubspec.yaml"],
            "mix.lock": ["mix.exs"],
        }
        return [str(source.parent / candidate) for candidate in mapping.get(source.name, [])]

    @staticmethod
    def _normalise_package_name(name: str, ecosystem: str) -> str:
        return normalise_package_name(name, ecosystem)

    def _manifest_declares_dependency(self, manifest_path: Path, package: str, ecosystem: str) -> bool | None:
        package_norm = self._normalise_package_name(package, ecosystem)
        try:
            content = manifest_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None

        try:
            if manifest_path.name == "package.json":
                data = json.loads(content)
                deps = {
                    **(data.get("dependencies") or {}),
                    **(data.get("devDependencies") or {}),
                    **(data.get("optionalDependencies") or {}),
                    **(data.get("peerDependencies") or {}),
                }
                return self._normalise_package_name(package, ecosystem) in {
                    self._normalise_package_name(dep_name, ecosystem) for dep_name in deps
                }

            if manifest_path.name == "pubspec.yaml":
                data = yaml.safe_load(content) or {}
                deps = {
                    **(data.get("dependencies") or {}),
                    **(data.get("dev_dependencies") or {}),
                }
                return package_norm in {
                    self._normalise_package_name(dep_name, ecosystem) for dep_name in deps
                }

            if manifest_path.name == "composer.json":
                data = json.loads(content)
                deps = {
                    **(data.get("require") or {}),
                    **(data.get("require-dev") or {}),
                }
                return package_norm in {
                    self._normalise_package_name(dep_name, ecosystem) for dep_name in deps if dep_name != "php"
                }

            if manifest_path.name == "Gemfile":
                return re.search(
                    rf"""gem\s+["']{re.escape(package_norm.replace("-", "_"))}["']""",
                    content,
                    re.IGNORECASE,
                ) is not None

            if manifest_path.name == "mix.exs":
                patterns = [
                    rf"""\{{\s*:{re.escape(package_norm.replace("-", "_"))}\s*,""",
                    rf"""\{{\s*["']{re.escape(package_norm)}["']\s*,""",
                ]
                return any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)

            if manifest_path.name == "go.mod":
                return re.search(rf"""^\s*{re.escape(package)}\s+v""", content, re.MULTILINE) is not None

            if manifest_path.name == "Cargo.toml" and tomllib is not None:
                data = tomllib.loads(content)
                dep_sections = [
                    data.get("dependencies") or {},
                    data.get("dev-dependencies") or {},
                    data.get("build-dependencies") or {},
                    ((data.get("target") or {})),
                ]
                direct: set[str] = set()
                for section in dep_sections[:3]:
                    direct.update(section.keys())
                targets = dep_sections[3]
                if isinstance(targets, dict):
                    for target_cfg in targets.values():
                        if isinstance(target_cfg, dict):
                            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                                direct.update((target_cfg.get(key) or {}).keys())
                return package_norm in {
                    self._normalise_package_name(dep_name, ecosystem) for dep_name in direct
                }
        except Exception:
            return None

        return None

    def _is_known_transitive_dependency(self, dep, repo_root: Path) -> bool:
        source_file = dep.source_file or ""
        if Path(source_file).name not in LOCKFILE_NAMES:
            return False

        cache_key = (source_file, dep.name)
        if cache_key in self._direct_dependency_cache:
            cached = self._direct_dependency_cache[cache_key]
            return cached is False

        manifest_candidates = self._manifest_candidates(source_file)
        if not manifest_candidates:
            self._direct_dependency_cache[cache_key] = None
            return False

        found_manifest = False
        for candidate in manifest_candidates:
            manifest_path = repo_root / candidate
            if not manifest_path.exists():
                continue
            found_manifest = True
            direct = self._manifest_declares_dependency(manifest_path, dep.name, dep.ecosystem)
            if direct is True:
                self._direct_dependency_cache[cache_key] = True
                return False
            if direct is False:
                self._direct_dependency_cache[cache_key] = False
                return True

        self._direct_dependency_cache[cache_key] = None if found_manifest else None
        return False

    def _classify_relevance(self, dep, usage_hits: list[dict], repo_root: Path) -> tuple[str, str]:
        hits = self._dedupe_usage_hits(usage_hits)
        non_test_hits = [hit for hit in hits if not self._is_test_path(hit.get("file", ""))]
        direct_import_hits = [hit for hit in non_test_hits if hit.get("kind") == "import"]
        reference_hits = [hit for hit in non_test_hits if hit.get("kind") == "reference"]
        test_hits = [hit for hit in hits if self._is_test_path(hit.get("file", ""))]

        if direct_import_hits:
            files = ", ".join(hit["file"] for hit in direct_import_hits[:3])
            return "used", f"Direct import/use detected in: {files}"
        if reference_hits:
            files = ", ".join(hit["file"] for hit in reference_hits[:3])
            return "likely_used", f"Package symbols referenced in: {files}"
        if dep.is_dev or (test_hits and not non_test_hits):
            files = ", ".join(hit["file"] for hit in test_hits[:3]) if test_hits else dep.source_file or "manifest"
            return "test_only", f"Dependency appears limited to development or test code: {files}"
        if self._is_known_transitive_dependency(dep, repo_root):
            return "transitive_only", "Dependency is present in a lockfile but not declared in the adjacent manifest."
        return "unknown", "No direct usage evidence found in application code."

    @staticmethod
    def _normalise_relevance(value: str) -> str:
        mapping = {
            "used": "used",
            "in_use": "used",
            "likely_used": "likely_used",
            "likely-in-use": "likely_used",
            "transitive_only": "transitive_only",
            "transitive": "transitive_only",
            "lockfile_only": "transitive_only",
            "test_only": "test_only",
            "unused": "unknown",
            "unknown": "unknown",
        }
        return mapping.get((value or "").strip().lower(), "unknown")

    @staticmethod
    def _normalise_reachability(value: str) -> str:
        mapping = {
            "reachable": "reachable",
            "in_path": "reachable",
            "potentially_reachable": "potentially_reachable",
            "imported": "potentially_reachable",
            "maybe_reachable": "potentially_reachable",
            "no_path": "no_path_found",
            "no_path_found": "no_path_found",
            "not_reachable": "no_path_found",
            "not_applicable": "not_applicable",
            "dev_only": "not_applicable",
            "test_only": "not_applicable",
        }
        return mapping.get((value or "").strip().lower(), "unknown")

    @staticmethod
    def _symbol_tokens(symbol: str) -> set[str]:
        clean = (symbol or "").strip().strip("`'\"")
        if not clean:
            return set()
        clean = re.sub(r"\(.*$", "", clean).strip()
        dotted = clean.replace("::", ".").replace("->", ".").replace("#", ".")
        tokens = {clean, dotted}
        tokens.update(part for part in dotted.split(".") if part)
        return {token.lower() for token in tokens if len(token) >= 2}

    @staticmethod
    def _match_import_resolution(package: str, ecosystem: str, import_module: str) -> tuple[float, str] | None:
        match = match_external_import_to_package(package, ecosystem, import_module)
        if not match:
            return None
        return float(match["confidence"]), str(match["kind"])

    def _find_vulnerable_function_usage(self, ctx: ScanContext, dep, finding, usage_hits: list[dict]) -> list[dict]:
        vulnerable_functions = [
            func for func in (finding.vulnerable_functions or [])
            if isinstance(func, str) and func
        ]
        if not vulnerable_functions:
            return []

        repo_root = Path(ctx.repo_path)
        candidate_files = [
            hit.get("file", "")
            for hit in usage_hits
            if hit.get("file") and hit.get("source") == "import_graph"
        ]
        candidate_files = list(dict.fromkeys(candidate_files))
        if not candidate_files:
            return []

        evidence: list[dict] = []
        seen: set[tuple[str, str, int]] = set()
        for relative_path in candidate_files[:12]:
            analysis = ctx.file_analyses.get(relative_path)

            if analysis and getattr(analysis, "call_sites", None):
                for call_site in analysis.call_sites:
                    call_tokens = set()
                    call_tokens.update(self._symbol_tokens(getattr(call_site, "callee_name", "")))
                    call_tokens.update(self._symbol_tokens(getattr(call_site, "callee_object", "")))
                    call_tokens.update(self._symbol_tokens(getattr(call_site, "full_expression", "")))

                    for symbol in vulnerable_functions[:25]:
                        symbol_tokens = self._symbol_tokens(symbol)
                        if not symbol_tokens or not (call_tokens & symbol_tokens):
                            continue

                        line = int(getattr(call_site, "line", 0) or 0)
                        key = (relative_path, symbol, line)
                        if key in seen:
                            continue
                        seen.add(key)
                        evidence.append(
                            {
                                "file": relative_path,
                                "kind": "vulnerable_function",
                                "symbol": symbol,
                                "line": line,
                            }
                        )

            if any(hit.get("file") == relative_path for hit in evidence):
                continue

            full_path = repo_root / relative_path
            if not full_path.exists() or not full_path.is_file():
                continue
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore").lower()
            except Exception:
                continue

            for symbol in vulnerable_functions[:25]:
                tokens = self._symbol_tokens(symbol)
                if not tokens:
                    continue
                if any(
                    re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", content)
                    for token in tokens
                ):
                    key = (relative_path, symbol, 0)
                    if key in seen:
                        continue
                    seen.add(key)
                    evidence.append(
                        {
                            "file": relative_path,
                            "kind": "vulnerable_function",
                            "symbol": symbol,
                        }
                    )

        return evidence

    def _infer_reachability(
        self,
        dep,
        relevance: str,
        usage_hits: list[dict],
        function_hits: list[dict],
    ) -> tuple[str, float]:
        if dep.is_dev or relevance == "test_only":
            return "not_applicable", 0.95
        if function_hits:
            return "reachable", 0.9 if any(hit.get("kind") == "import" for hit in usage_hits) else 0.8
        if relevance == "used":
            return "potentially_reachable", 0.7
        if relevance == "likely_used":
            return "potentially_reachable", 0.55
        if relevance == "transitive_only":
            return "no_path_found", 0.8
        return "no_path_found", 0.45

    def _compute_risk_score(
        self,
        ctx: ScanContext,
        dep,
        finding,
        relevance: str,
        reachability_status: str,
        usage_hits: list[dict],
        function_hits: list[dict],
    ) -> tuple[float, dict]:
        severity = (finding.severity or "medium").lower()
        base = {
            "critical": 850.0,
            "high": 700.0,
            "medium": 450.0,
            "low": 180.0,
            "info": 50.0,
        }.get(severity, 300.0)

        if finding.cvss_score is not None:
            base = max(base, min(900.0, finding.cvss_score * 100.0))

        modifiers: dict[str, float] = {"base": round(base, 1)}
        score = base

        reachability_bonus = {
            "reachable": 180.0,
            "potentially_reachable": 90.0,
            "no_path_found": -90.0,
            "not_applicable": -220.0,
            "unknown": 0.0,
        }.get(reachability_status, 0.0)
        score += reachability_bonus
        modifiers["reachability"] = round(reachability_bonus, 1)

        relevance_bonus = {
            "used": 80.0,
            "likely_used": 35.0,
            "transitive_only": -70.0,
            "test_only": -180.0,
            "unknown": 0.0,
        }.get(relevance, 0.0)
        score += relevance_bonus
        modifiers["relevance"] = round(relevance_bonus, 1)

        if function_hits:
            score += 120.0
            modifiers["vulnerable_function_match"] = 120.0

        if dep.is_dev:
            score -= 120.0
            modifiers["dev_dependency"] = -120.0

        if finding.fixed_version:
            score += 25.0
            modifiers["fix_available"] = 25.0

        hot_files = set(ctx.get_hot_files(limit=20))
        if any(hit.get("file") in hot_files for hit in usage_hits + function_hits):
            score += 40.0
            modifiers["hot_file_usage"] = 40.0

        score = max(0.0, min(1000.0, score))
        modifiers["final"] = round(score, 1)
        return round(score, 1), modifiers

    @property
    def name(self) -> str:
        return "dependency_risk"

    async def execute(self, ctx: ScanContext) -> None:
        ctx.current_task = "Assessing dependency risks"
        await self.emit(ctx, "Analysing dependency vulnerabilities...")

        # Load dependency findings from DB
        async with async_session() as session:
            result = await session.execute(
                select(DependencyFinding, Dependency)
                .join(Dependency, DependencyFinding.dependency_id == Dependency.id)
                .where(DependencyFinding.scan_id == ctx.scan_id)
            )
            dep_findings = result.all()

        if not dep_findings:
            await self.emit(ctx, "No dependency vulnerabilities to assess")
            return

        await self.emit(ctx, f"Assessing {len(dep_findings)} dependency vulnerabilities...")

        # Build context: find which files import these packages
        import_usage = await self._find_import_usage(ctx, dep_findings)

        # Batch assess with AI
        batch_size = 8
        for i in range(0, len(dep_findings), batch_size):
            if ctx.cancelled:
                return

            batch = dep_findings[i:i + batch_size]
            await self._assess_batch(ctx, batch, import_usage)

        assessed_count = len([df for df, _ in dep_findings if df.relevance != "unknown"])
        await self.emit(ctx, f"Dependency assessment complete. {assessed_count} packages assessed.")

        await self.log_decision(
            ctx,
            action="dependency_assessment_complete",
            output_summary=f"Assessed {len(dep_findings)} vulnerable dependencies",
        )

    async def _find_import_usage(self, ctx: ScanContext, dep_findings: list) -> dict[str, list[dict]]:
        """Find which files import the vulnerable packages."""
        usage: dict[str, list[dict]] = {}

        package_names = set()
        package_meta: dict[str, str] = {}
        for df, dep in dep_findings:
            package_names.add(dep.name)
            package_meta[dep.name] = dep.ecosystem

        for file_path, resolutions in ctx.import_graph.items():
            for res in resolutions:
                if not getattr(res, "is_external", False):
                    continue

                import_module = getattr(res, "import_module", "")
                if not import_module:
                    continue

                for pkg in package_names:
                    ecosystem = package_meta.get(pkg, "")
                    match = self._match_import_resolution(pkg, ecosystem, import_module)
                    if not match:
                        continue

                    confidence, kind = match
                    usage.setdefault(pkg, []).append(
                        {
                            "file": file_path,
                            "kind": kind,
                            "symbol": import_module,
                            "confidence": round(confidence, 2),
                            "source": "import_graph",
                        }
                    )

        missing_packages = {pkg for pkg in package_names if not usage.get(pkg)}
        if missing_packages:
            repo = Path(ctx.repo_path)
            candidate_files = set(ctx.import_graph.keys()) | set(ctx.file_analyses.keys())

            if not candidate_files:
                async with async_session() as session:
                    result = await session.execute(select(File).where(File.scan_id == ctx.scan_id))
                    candidate_files = {file_rec.path for file_rec in result.scalars().all() if file_rec.path}

            for relative_path in sorted(candidate_files):
                full_path = repo / relative_path
                if not full_path.exists() or not full_path.is_file():
                    continue

                try:
                    content_lower = full_path.read_text(encoding="utf-8", errors="ignore").lower()
                except Exception:
                    continue

                for pkg in list(missing_packages):
                    ecosystem = package_meta.get(pkg, "")
                    tokens = self._dependency_usage_tokens(pkg, ecosystem)
                    pattern_kinds: list[tuple[str, str]] = []
                    for token in tokens:
                        pattern_kinds.extend(
                            [
                                (f"import {token}", "import"),
                                (f"from {token}", "import"),
                                (f"require('{token}", "import"),
                                (f'require("{token}', "import"),
                                (f"import '{token}", "import"),
                                (f'import "{token}', "import"),
                                (f"alias {token}", "import"),
                                (f"use {token}", "import"),
                                (f"{token}.", "reference"),
                            ]
                        )

                    matched_kind = next(
                        (kind for pattern, kind in pattern_kinds if pattern in content_lower),
                        None,
                    )
                    if not matched_kind:
                        continue

                    usage.setdefault(pkg, []).append(
                        {
                            "file": relative_path,
                            "kind": matched_kind,
                            "confidence": 0.45,
                            "source": "text_fallback",
                        }
                    )
                    if matched_kind == "import":
                        missing_packages.discard(pkg)

        return {
            package: self._dedupe_usage_hits(hits)
            for package, hits in usage.items()
        }

    async def _assess_batch(
        self,
        ctx: ScanContext,
        batch: list,
        import_usage: dict[str, list[dict]],
    ):
        """Assess a batch of dependency findings with AI."""
        # Build prompt
        parts = [
            f"Application: {ctx.app_summary[:300]}" if ctx.app_summary else "",
            f"Languages: {', '.join(ctx.languages)}",
            f"Frameworks: {', '.join(ctx.frameworks)}",
            "",
            "## Vulnerable Dependencies to Assess",
        ]

        for df, dep in batch:
            pkg_usage = import_usage.get(dep.name, [])
            pkg_files = [hit["file"] for hit in pkg_usage]
            heuristic_relevance, heuristic_assessment = self._classify_relevance(
                dep, pkg_usage, Path(ctx.repo_path)
            )
            parts.append(
                f"\n### {dep.name} v{dep.version} ({dep.ecosystem})"
                f"\n- Advisory: {df.advisory_id}"
                f"\n- Severity: {df.severity}"
                f"\n- Summary: {df.summary}"
                f"\n- Affected range: {df.affected_range}"
                f"\n- Fixed in: {df.fixed_version}"
                f"\n- Is dev dependency: {dep.is_dev}"
                f"\n- Source file: {dep.source_file}"
                f"\n- Usage evidence: {self._summarise_usage_hits(pkg_usage)}"
                f"\n- Heuristic relevance: {heuristic_relevance}"
                f"\n- Heuristic assessment: {heuristic_assessment}"
            )

            # Read a snippet from files that use this package
            if pkg_files and self.llm:
                for fp in pkg_files[:2]:
                    snippet = await self.read_file(ctx, fp, max_lines=50)
                    parts.append(f"\n**Usage in {fp}:**\n```\n{snippet[:500]}\n```")

        user_content = "\n".join(parts)

        if not self.llm:
            # No AI available — use heuristic
            await self._heuristic_assess(ctx, batch, import_usage)
            return

        try:
            result = await self.llm.chat_json(SYSTEM_PROMPT, user_content, max_tokens=2000)
            ctx.ai_calls_made += 1
        except Exception as e:
            await self.emit(ctx, f"Dependency assessment batch failed: {e}", level="warn")
            await self._heuristic_assess(ctx, batch, import_usage)
            return

        # Update findings
        assessments = result.get("assessments", [])
        async with async_session() as session:
            for assessment in assessments:
                pkg_name = assessment.get("package", "")
                advisory_id = assessment.get("advisory_id", "")

                for df, dep in batch:
                    if dep.name == pkg_name and (not advisory_id or df.advisory_id == advisory_id):
                        # Reload in this session
                        db_df = await session.get(DependencyFinding, df.id)
                        if db_df:
                            pkg_usage = import_usage.get(dep.name, [])
                            function_hits = self._find_vulnerable_function_usage(
                                ctx, dep, db_df, pkg_usage
                            )
                            relevance = self._normalise_relevance(assessment.get("relevance", "unknown"))
                            ai_reachability = self._normalise_reachability(
                                assessment.get("reachability_status", "")
                            )
                            heuristic_reachability, heuristic_confidence = self._infer_reachability(
                                dep,
                                relevance,
                                pkg_usage,
                                function_hits,
                            )
                            reachability = (
                                ai_reachability if ai_reachability != "unknown" else heuristic_reachability
                            )
                            risk_score, risk_factors = self._compute_risk_score(
                                ctx,
                                dep,
                                db_df,
                                relevance,
                                reachability,
                                pkg_usage,
                                function_hits,
                            )
                            db_df.relevance = relevance
                            db_df.usage_evidence = self._dedupe_usage_hits(pkg_usage) + function_hits
                            db_df.reachability_status = reachability
                            db_df.reachability_confidence = heuristic_confidence
                            db_df.risk_score = risk_score
                            db_df.risk_factors = risk_factors
                            db_df.ai_assessment = assessment.get("assessment", "")
                        break

            await session.commit()

    async def _heuristic_assess(self, ctx: ScanContext, batch: list, import_usage: dict[str, list[dict]]):
        """Heuristic assessment when AI is not available."""
        async with async_session() as session:
            repo_root = Path(ctx.repo_path)
            for df, dep in batch:
                db_df = await session.get(DependencyFinding, df.id)
                if not db_df:
                    continue

                pkg_usage = import_usage.get(dep.name, [])
                relevance, assessment = self._classify_relevance(dep, pkg_usage, repo_root)
                function_hits = self._find_vulnerable_function_usage(ctx, dep, db_df, pkg_usage)
                reachability, reachability_confidence = self._infer_reachability(
                    dep,
                    relevance,
                    pkg_usage,
                    function_hits,
                )
                risk_score, risk_factors = self._compute_risk_score(
                    ctx,
                    dep,
                    db_df,
                    relevance,
                    reachability,
                    pkg_usage,
                    function_hits,
                )
                db_df.relevance = relevance
                db_df.usage_evidence = self._dedupe_usage_hits(pkg_usage) + function_hits
                db_df.reachability_status = reachability
                db_df.reachability_confidence = reachability_confidence
                db_df.risk_score = risk_score
                db_df.risk_factors = risk_factors
                db_df.ai_assessment = assessment

            await session.commit()
