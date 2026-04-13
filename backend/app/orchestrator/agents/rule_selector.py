"""Rule Selection Agent — choose targeted scanner rules for follow-up passes."""

import json
import logging
import os
from pathlib import Path

from app.config import settings
from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import ScanContext
from app.scanners.registry import get_available_scanners

logger = logging.getLogger(__name__)

# Rule directory mappings — maps risk themes to actual directory paths
# under data/semgrep-rules/. These match the downloaded community rules.
SEMGREP_RULE_DIRS = {
    # Language-specific subdirectories (e.g., python/django, java/spring)
    "python_django": "python/django",
    "python_flask": "python/flask",
    "python_fastapi": "python/fastapi",
    "python_sqlalchemy": "python/sqlalchemy",
    "python_crypto": "python/cryptography",
    "python_jwt": "python/jwt",
    "python_lang": "python/lang",
    "python_requests": "python/requests",
    "python_boto3": "python/boto3",
    "python_pymongo": "python/pymongo",
    "javascript_express": "javascript/express",
    "javascript_lang": "javascript/lang",
    "javascript_browser": "javascript/browser",
    "javascript_jsonwebtoken": "javascript/jsonwebtoken",
    "javascript_audit": "javascript/audit",
    "typescript_all": "typescript",
    "java_spring": "java/spring",
    "java_lang": "java/lang",
    "java_servlets": "java/servlets",
    "java_android": "java/android",
    "go_all": "go",
    "ruby_all": "ruby",
    "php_all": "php",
    "csharp_all": "csharp",
    "kotlin_all": "kotlin",
    "terraform_all": "terraform",
    "dockerfile_all": "dockerfile",
    "yaml_all": "yaml",
    "generic_all": "generic",
}

# Risk theme to rule directory mapping — for AI-driven selection
RISK_THEME_DIRS = {
    "sqli": ["python/django", "python/flask", "python/sqlalchemy", "python/lang",
             "javascript/lang", "java/lang", "java/spring", "ruby", "php", "csharp"],
    "xss": ["python/django", "python/flask", "python/jinja2",
            "javascript/browser", "javascript/express", "javascript/lang", "ruby", "php"],
    "command_injection": ["python/lang", "javascript/lang", "java/lang", "ruby", "php", "go"],
    "path_traversal": ["python/lang", "javascript/lang", "java/lang", "go", "ruby", "php"],
    "ssrf": ["python/requests", "javascript/lang", "java/lang", "go"],
    "deserialization": ["python/lang", "java/lang", "ruby", "php", "csharp", "kotlin"],
    "crypto": ["python/cryptography", "python/pycryptodome", "javascript/lang", "java/lang", "go", "csharp"],
    "auth": ["python/django", "python/flask", "python/jwt",
             "javascript/express", "javascript/jsonwebtoken", "java/spring"],
    "xxe": ["python/lang", "java/lang", "csharp", "php"],
    "csrf": ["python/django", "python/flask", "java/spring", "ruby"],
    "open_redirect": ["python/django", "python/flask", "javascript/express", "java/spring"],
    "info_disclosure": ["generic", "python/lang", "javascript/lang"],
    "hardcoded_secrets": ["generic", "python/lang", "javascript/lang"],
    "infrastructure": ["terraform", "dockerfile", "yaml"],
    "jwt": ["python/jwt", "javascript/jsonwebtoken", "javascript/jose", "java/java-jwt", "java/jjwt"],
    "nosql": ["python/pymongo", "javascript/lang"],
    "aws": ["python/boto3", "terraform"],
}

BANDIT_RULE_GROUPS = {
    "sqli": ["B608"],           # SQL injection via string formatting
    "command_injection": ["B602", "B603", "B604", "B605", "B607"],
    "deserialization": ["B301", "B302", "B303"],  # pickle, marshal, yaml
    "crypto": ["B303", "B304", "B305", "B306", "B324"],
    "path_traversal": ["B322"],  # input() in Python 2
    "hardcoded_secrets": ["B105", "B106", "B107"],
    "auth": ["B501", "B502", "B503", "B504", "B505"],  # SSL/TLS issues
    "exec": ["B102"],           # exec used
}

# ESLint targeted rules for security follow-up
ESLINT_RULE_GROUPS = {
    "xss": ["no-eval", "no-implied-eval", "no-new-func", "no-script-url"],
    "injection": ["no-eval", "no-new-func", "no-implied-eval"],
    "prototype_pollution": ["no-proto", "no-extend-native", "no-iterator"],
    "filesystem": ["no-path-concat"],
    "crypto": ["no-restricted-properties"],
}

CODEQL_QUERY_GROUPS = {
    "python": ["python-security-and-quality.qls", "python-security-experimental.qls"],
    "javascript": ["javascript-security-and-quality.qls", "javascript-security-experimental.qls"],
    "typescript": ["javascript-security-and-quality.qls", "javascript-security-experimental.qls"],
    "java": ["java-security-and-quality.qls", "java-security-experimental.qls"],
    "go": ["go-security-and-quality.qls", "go-security-experimental.qls"],
    "ruby": ["ruby-security-and-quality.qls", "ruby-security-experimental.qls"],
    "csharp": ["csharp-security-and-quality.qls", "csharp-security-experimental.qls"],
    "cpp": ["cpp-security-and-quality.qls", "cpp-security-experimental.qls"],
    "c": ["cpp-security-and-quality.qls", "cpp-security-experimental.qls"],
    "swift": ["swift-security-and-quality.qls", "swift-security-experimental.qls"],
}

SCANNER_TARGET_SUFFIXES = {
    "bandit": {".py", ".pyi"},
    "eslint": {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"},
}

SEMGREP_DIR_SIGNAL_HINTS = {
    "python/django": {"django"},
    "python/flask": {"flask"},
    "python/fastapi": {"fastapi"},
    "python/sqlalchemy": {"sqlalchemy"},
    "python/requests": {"requests"},
    "python/boto3": {"boto3"},
    "python/pymongo": {"pymongo"},
    "python/jinja2": {"jinja2"},
    "python/cryptography": {"cryptography"},
    "python/pycryptodome": {"pycryptodome"},
    "python/jwt": {"jwt", "pyjwt"},
    "javascript/express": {"express"},
    "javascript/react": {"react"},
    "typescript/react": {"react"},
    "javascript/browser": {"react", "vue", "angular", "nextjs", "nuxtjs", "vite", "tailwind", "svelte"},
    "javascript/vue": {"vue", "nuxtjs"},
    "javascript/angular": {"angular"},
    "typescript/angular": {"angular"},
    "typescript/nestjs": {"nestjs", "@nestjs/core", "@nestjs/common"},
    "typescript/aws-cdk": {"aws-cdk", "aws-cdk-lib"},
    "javascript/jsonwebtoken": {"jsonwebtoken"},
    "javascript/jose": {"jose"},
    "yaml/kubernetes": {"kubernetes", "helm"},
}

SYSTEM_PROMPT = """You are a security tool expert. Based on the application's technology stack,
identified attack surface, and investigation focus areas, select the most relevant
scanner rules to run in a targeted follow-up pass.

Your goal is to maximise signal (real findings) and minimise noise (false positives).
Only recommend rules that are relevant to the actual code being scanned.

Respond with JSON:
{
  "semgrep_rule_dirs": ["rule directory paths from the available set — e.g. 'python/django', 'javascript/express'"],
  "risk_themes": ["risk theme names — e.g. 'sqli', 'xss', 'auth', 'jwt'"],
  "bandit_rules": ["bandit test IDs — e.g. 'B608', 'B602'"],
  "eslint_rules": ["ESLint rule names — e.g. 'no-eval', 'no-proto'"],
  "codeql_queries": ["CodeQL suite names — e.g. 'python-security-experimental.qls'"],
  "target_files": ["specific files to scan, or empty for all"],
  "reasoning": "Why these rules were selected"
}"""


class RuleSelectorAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "rule_selector"

    async def execute(self, ctx: ScanContext) -> None:
        ctx.current_task = "Selecting targeted scanner rules"
        await self.emit(ctx, "Selecting targeted scanner rules for follow-up...")

        budget = ctx.iteration_budget.get("targeted_reruns", 0)
        if budget <= 0:
            await self.emit(ctx, "No targeted reruns budgeted for this scan mode")
            return

        # Ask AI which rules to run
        user_prompt = self._build_prompt(ctx)

        try:
            result = await self.llm.chat_json(SYSTEM_PROMPT, user_prompt, max_tokens=2000)
            ctx.ai_calls_made += 1
        except Exception as e:
            await self.emit(ctx, f"Rule selection failed: {e}", level="warn")
            # Fall back to heuristic selection
            result = self._heuristic_selection(ctx)

        # Execute targeted scans
        available = ctx.scanners if ctx.scanners else await get_available_scanners()
        repo_path = Path(ctx.repo_path)

        # Collect rule directories from both direct dirs and risk themes
        semgrep_dirs = result.get("semgrep_rule_dirs", [])
        risk_themes = result.get("risk_themes", result.get("semgrep_rules", []))
        bandit_rules = result.get("bandit_rules", [])
        eslint_rules = result.get("eslint_rules", [])
        codeql_queries = list(dict.fromkeys(result.get("codeql_queries", [])))
        target_files = result.get("target_files", [])
        safe_target_files = target_files or ctx.get_hot_files(limit=12)

        # Resolve risk themes to directories
        for theme in risk_themes:
            if theme in RISK_THEME_DIRS:
                semgrep_dirs.extend(RISK_THEME_DIRS[theme])

        package_signals = set()
        if "semgrep" in available:
            try:
                package_signals = available["semgrep"]._collect_package_signals(repo_path)
            except Exception:
                package_signals = set()

        semgrep_dirs = self._optimise_semgrep_dirs(ctx, semgrep_dirs, package_signals=package_signals)

        runs_done = 0

        # Targeted Semgrep
        if semgrep_dirs and "semgrep" in available and runs_done < budget:
            if semgrep_dirs:
                labels = [d.split("/")[-1] for d in semgrep_dirs[:4]]
                ctx.current_task = f"Running targeted Semgrep ({', '.join(labels)})"
                await self.emit(ctx, f"Running targeted Semgrep: {', '.join(labels)} ({len(semgrep_dirs)} rule dirs)")

                output = await available["semgrep"].run_targeted(
                    repo_path,
                    files=safe_target_files or [],
                    rules=semgrep_dirs,
                )

                summary = ctx.record_scanner_run(
                    "semgrep_targeted",
                    success=output.success,
                    hit_count=len(output.hits),
                    duration_ms=output.duration_ms,
                    errors=output.errors,
                )
                if output.hits:
                    await self.emit(
                        ctx,
                        f"Targeted Semgrep found {len(output.hits)} additional hits",
                        detail=summary,
                    )
                    await self._persist_targeted_hits(ctx, "semgrep_targeted", output.hits, repo_path)
                elif summary["errors"]:
                    await self.emit(ctx, "Targeted Semgrep completed with scanner errors", level="warn", detail=summary)

                runs_done += 1

        # Targeted Bandit
        if bandit_rules and "bandit" in available and "python" in ctx.languages and runs_done < budget:
            bandit_target_files = self._filter_target_files("bandit", safe_target_files)
            if not bandit_target_files:
                await self.emit(ctx, "Skipping targeted Bandit; no Python files matched the follow-up target set.")
            else:
                ctx.current_task = f"Running targeted Bandit ({', '.join(bandit_rules[:5])})"
                await self.emit(ctx, f"Running targeted Bandit: {', '.join(bandit_rules[:5])}")

                output = await available["bandit"].run_targeted(
                    repo_path,
                    files=bandit_target_files,
                    rules=bandit_rules,
                )

                summary = ctx.record_scanner_run(
                    "bandit_targeted",
                    success=output.success,
                    hit_count=len(output.hits),
                    duration_ms=output.duration_ms,
                    errors=output.errors,
                )
                if output.hits:
                    await self.emit(
                        ctx,
                        f"Targeted Bandit found {len(output.hits)} additional hits",
                        detail=summary,
                    )
                    await self._persist_targeted_hits(ctx, "bandit_targeted", output.hits, repo_path)
                elif summary["errors"]:
                    await self.emit(ctx, "Targeted Bandit completed with scanner errors", level="warn", detail=summary)

                runs_done += 1

        # Targeted ESLint
        if eslint_rules and "eslint" in available and any(
            l in ctx.languages for l in ("javascript", "typescript")
        ) and runs_done < budget:
            eslint_target_files = self._filter_target_files("eslint", safe_target_files)
            if not eslint_target_files:
                await self.emit(ctx, "Skipping targeted ESLint; no JS/TS files matched the follow-up target set.")
            else:
                ctx.current_task = f"Running targeted ESLint ({', '.join(eslint_rules[:5])})"
                await self.emit(ctx, f"Running targeted ESLint: {', '.join(eslint_rules[:5])}")

                output = await available["eslint"].run_targeted(
                    repo_path,
                    files=eslint_target_files,
                    rules=eslint_rules,
                )

                summary = ctx.record_scanner_run(
                    "eslint_targeted",
                    success=output.success,
                    hit_count=len(output.hits),
                    duration_ms=output.duration_ms,
                    errors=output.errors,
                )
                if output.hits:
                    await self.emit(
                        ctx,
                        f"Targeted ESLint found {len(output.hits)} additional hits",
                        detail=summary,
                    )
                    await self._persist_targeted_hits(ctx, "eslint_targeted", output.hits, repo_path)
                elif summary["errors"]:
                    await self.emit(ctx, "Targeted ESLint completed with scanner errors", level="warn", detail=summary)

                runs_done += 1

        # Targeted CodeQL
        if codeql_queries and "codeql" in available and runs_done < budget:
            ctx.current_task = f"Running targeted CodeQL ({', '.join(codeql_queries[:2])})"
            await self.emit(ctx, f"Running targeted CodeQL: {', '.join(codeql_queries[:2])}")

            output = await available["codeql"].run_targeted(
                repo_path,
                files=safe_target_files or [],
                rules=codeql_queries,
            )

            summary = ctx.record_scanner_run(
                "codeql_targeted",
                success=output.success,
                hit_count=len(output.hits),
                duration_ms=output.duration_ms,
                errors=output.errors,
            )
            if output.hits:
                await self.emit(
                    ctx,
                    f"Targeted CodeQL found {len(output.hits)} additional hits",
                    detail=summary,
                )
                await self._persist_targeted_hits(ctx, "codeql_targeted", output.hits, repo_path)
            elif summary["errors"]:
                await self.emit(ctx, "Targeted CodeQL completed with scanner errors", level="warn", detail=summary)

            runs_done += 1

        await self.emit(ctx, f"Targeted scanning complete. {runs_done} follow-up runs executed.")
        await self.emit_progress(ctx, task=f"Targeted scanning done — {runs_done} runs, {sum(v for k, v in ctx.scanner_hit_counts.items() if k.endswith('_targeted'))} new hits")

        await self.log_decision(
            ctx,
            action="rule_selection_complete",
            reasoning=result.get("reasoning", ""),
            output_summary=(
                f"Selected {len(semgrep_dirs)} semgrep dirs, {len(bandit_rules)} bandit rules, "
                f"{len(eslint_rules)} eslint rules, {len(codeql_queries)} codeql suites"
            ),
        )

    async def _persist_targeted_hits(
        self, ctx: ScanContext, scanner_name: str, hits: list, repo_path: Path
    ):
        """Persist targeted scanner hits to the database AND boost affected files."""
        from sqlalchemy import select
        from app.database import async_session
        from app.models.file import File
        from app.models.scanner_result import ScannerResult

        async with async_session() as session:
            for hit in hits:
                # Normalise path
                rel_path = hit.file_path
                if str(repo_path) in rel_path:
                    rel_path = rel_path.replace(str(repo_path), "").lstrip("/\\")
                rel_path = rel_path.replace("\\", "/")

                # Find file record
                file_result = await session.execute(
                    select(File).where(File.scan_id == ctx.scan_id, File.path == rel_path)
                )
                file_rec = file_result.scalar_one_or_none()

                sr = ScannerResult(
                    scan_id=ctx.scan_id,
                    file_id=file_rec.id if file_rec else None,
                    scanner=scanner_name,
                    rule_id=hit.rule_id,
                    severity=hit.severity,
                    message=hit.message,
                    start_line=hit.start_line,
                    end_line=hit.end_line,
                    snippet=hit.snippet,
                    extra_data=hit.metadata,
                )
                session.add(sr)

                # Boost the file so the mini-investigator picks it up
                ctx.boost_file(rel_path, 10.0, f"targeted {scanner_name} hit: {hit.rule_id}")

            await session.commit()

        # Re-prioritise so boosted files are at the top
        ctx.reprioritise_queue()

    def _build_prompt(self, ctx: ScanContext) -> str:
        parts = [
            f"Languages: {', '.join(ctx.languages)}",
            f"Frameworks: {', '.join(ctx.frameworks)}",
            f"App summary: {ctx.app_summary[:500]}" if ctx.app_summary else "",
            f"Attack surface: {', '.join(ctx.attack_surface[:10])}",
        ]

        if ctx.candidate_findings:
            parts.append("\nCandidate findings so far:")
            for f in ctx.candidate_findings[:10]:
                parts.append(f"- {f.title} ({f.category}, {f.severity})")

        # Show ACTUAL available rule directories on disk
        rules_path = settings.semgrep_rules_path
        available_dirs = []
        if rules_path.exists():
            for lang_dir in sorted(rules_path.iterdir()):
                if lang_dir.is_dir() and not lang_dir.name.startswith("_"):
                    subdirs = [d.name for d in lang_dir.iterdir() if d.is_dir()]
                    if subdirs:
                        for sd in subdirs[:8]:
                            available_dirs.append(f"{lang_dir.name}/{sd}")
                    else:
                        available_dirs.append(lang_dir.name)

        parts.append(f"\nAvailable Semgrep rule directories ({len(available_dirs)}):")
        for d in available_dirs[:40]:
            parts.append(f"  - {d}")
        if len(available_dirs) > 40:
            parts.append(f"  ... and {len(available_dirs) - 40} more")

        parts.append(f"\nAvailable risk themes: {list(RISK_THEME_DIRS.keys())}")

        # Show what Bandit groups contain so AI can pick precisely
        parts.append(f"\nAvailable Bandit rule groups:")
        for group, rules in BANDIT_RULE_GROUPS.items():
            parts.append(f"  - {group}: {', '.join(rules)}")

        # Show ESLint groups with their rules
        parts.append(f"\nAvailable ESLint rule groups:")
        for group, rules in ESLINT_RULE_GROUPS.items():
            parts.append(f"  - {group}: {', '.join(rules)}")
        parts.append("  Other available: no-buffer-constructor, no-path-concat, no-caller, no-return-assign")

        codeql_suites = []
        for lang in ctx.languages:
            codeql_suites.extend(CODEQL_QUERY_GROUPS.get(lang, []))
        codeql_suites = list(dict.fromkeys(codeql_suites))
        if codeql_suites:
            parts.append(f"\nAvailable CodeQL follow-up suites:")
            for suite in codeql_suites:
                parts.append(f"  - {suite}")

        # Tell the AI what already ran in baseline so it doesn't repeat
        if ctx.baseline_rule_dirs:
            count_hint = (
                f" (~{ctx.baseline_rule_count} rules across {len(ctx.baseline_rule_dirs)} packs)"
                if ctx.baseline_rule_count else ""
            )
            parts.append(f"\nAlready scanned in baseline (DO NOT re-select){count_hint}:")
            for d in ctx.baseline_rule_dirs[:15]:
                parts.append(f"  - {d}")

        # Show baseline scanner hit counts so AI knows what produced results
        if ctx.scanner_hit_counts:
            parts.append(f"\nBaseline scanner results:")
            for scanner, count in ctx.scanner_hit_counts.items():
                if not scanner.endswith("_targeted"):
                    parts.append(f"  - {scanner}: {count} hits")

        return "\n".join(parts)

    def _heuristic_selection(self, ctx: ScanContext) -> dict:
        """Fallback: select rules based on detected languages and frameworks."""
        dirs = []
        themes = []
        bandit = []
        codeql = []
        frameworks = {fw.lower() for fw in ctx.frameworks}

        if "python" in ctx.languages:
            if "django" in frameworks:
                dirs.append("python/django")
            if "flask" in frameworks:
                dirs.append("python/flask")
            if "fastapi" in frameworks:
                dirs.append("python/fastapi")
            if "sqlalchemy" in frameworks:
                dirs.append("python/sqlalchemy")
            themes.extend(["sqli", "command_injection", "deserialization"])
            bandit.extend(["B608", "B602", "B301", "B105"])
            codeql.extend(CODEQL_QUERY_GROUPS["python"])

        eslint = []

        if any(l in ctx.languages for l in ("javascript", "typescript")):
            if "express" in frameworks:
                dirs.append("javascript/express")
            if {"react", "vue", "angular", "nextjs", "nuxtjs", "vite", "tailwind"} & frameworks:
                dirs.append("javascript/browser")
            if "react" in frameworks:
                dirs.append("typescript/react" if "typescript" in ctx.languages else "javascript/react")
            if "angular" in frameworks and "typescript" in ctx.languages:
                dirs.append("typescript/angular")
            if "nestjs" in frameworks and "typescript" in ctx.languages:
                dirs.append("typescript/nestjs")
            themes.extend(["xss", "ssrf", "open_redirect", "nosql"])
            eslint.extend(["no-eval", "no-implied-eval", "no-new-func", "no-script-url", "no-proto"])
            if "typescript" in ctx.languages:
                codeql.extend(CODEQL_QUERY_GROUPS["typescript"])
            else:
                codeql.extend(CODEQL_QUERY_GROUPS["javascript"])

        if "java" in ctx.languages:
            dirs.extend(["java/lang", "java/spring", "java/servlets"])
            themes.extend(["xxe", "deserialization"])
            codeql.extend(CODEQL_QUERY_GROUPS["java"])

        if "go" in ctx.languages:
            dirs.append("go")
            themes.extend(["sqli", "command_injection"])
            codeql.extend(CODEQL_QUERY_GROUPS["go"])

        if "ruby" in ctx.languages:
            dirs.append("ruby")
            themes.extend(["sqli", "xss", "csrf"])
            codeql.extend(CODEQL_QUERY_GROUPS["ruby"])

        if "php" in ctx.languages:
            dirs.append("php")
            themes.extend(["sqli", "xss", "deserialization"])

        themes.extend(["hardcoded_secrets"])

        return {
            "semgrep_rule_dirs": list(dict.fromkeys(dirs)),
            "risk_themes": list(dict.fromkeys(themes)),
            "bandit_rules": list(set(bandit)),
            "eslint_rules": list(set(eslint)),
            "codeql_queries": list(dict.fromkeys(codeql)),
            "target_files": [],
            "reasoning": "Heuristic selection based on detected stack",
        }

    @staticmethod
    def _canonical_rule_ref(rule: str, rules_path: Path) -> str:
        if not rule:
            return ""
        value = str(rule).replace("\\", "/").strip("/")
        candidate = Path(value)
        if candidate.is_absolute():
            try:
                return str(candidate.resolve().relative_to(rules_path.resolve())).replace("\\", "/")
            except Exception:
                return ""
        return value

    def _expand_root_rule_dir(self, relative_dir: str, rules_path: Path) -> list[str]:
        candidate = rules_path / relative_dir
        if not candidate.exists() or not candidate.is_dir() or "/" in relative_dir:
            return [relative_dir]
        children = [
            f"{relative_dir}/{child.name}"
            for child in sorted(candidate.iterdir())
            if child.is_dir()
        ]
        return children or [relative_dir]

    @staticmethod
    def _rule_dir_matches_ctx(relative_dir: str, ctx: ScanContext) -> bool:
        if not relative_dir:
            return False
        languages = {lang.lower() for lang in getattr(ctx, "languages", [])}
        head = relative_dir.split("/", 1)[0].lower()
        if head in {"dockerfile", "terraform", "yaml", "generic"}:
            return True
        if head == "javascript":
            return bool({"javascript", "typescript"} & languages)
        if head == "typescript":
            return "typescript" in languages
        return head in languages

    def _optimise_semgrep_dirs(
        self,
        ctx: ScanContext,
        selected_dirs: list[str],
        *,
        package_signals: set[str] | None = None,
    ) -> list[str]:
        rules_path = settings.semgrep_rules_path
        baseline = {
            str(item).replace("\\", "/").strip("/")
            for item in (ctx.baseline_rule_dirs or [])
            if item
        }
        relevant_signals = {fw.lower() for fw in getattr(ctx, "frameworks", [])}
        relevant_signals.update(signal.lower() for signal in (package_signals or set()))
        optimised: list[str] = []
        seen: set[str] = set()
        for raw_rule in selected_dirs:
            canonical = self._canonical_rule_ref(raw_rule, rules_path)
            if not canonical:
                continue
            if os.name == "nt" and canonical == "generic":
                continue
            if not self._rule_dir_matches_ctx(canonical, ctx):
                continue
            for expanded in self._expand_root_rule_dir(canonical, rules_path):
                if not expanded or expanded in baseline or expanded in seen:
                    continue
                if not (rules_path / expanded).exists():
                    continue
                required_signals = SEMGREP_DIR_SIGNAL_HINTS.get(expanded)
                if required_signals and not (required_signals & relevant_signals):
                    continue
                seen.add(expanded)
                optimised.append(expanded)
        return optimised

    @staticmethod
    def _filter_target_files(scanner_name: str, files: list[str]) -> list[str]:
        allowed_suffixes = SCANNER_TARGET_SUFFIXES.get(scanner_name)
        if not allowed_suffixes:
            return list(dict.fromkeys(file for file in files if file))

        filtered: list[str] = []
        seen: set[str] = set()
        for file_path in files:
            if not file_path:
                continue
            normalised = str(file_path).replace("\\", "/")
            suffix = Path(normalised).suffix.lower()
            if suffix not in allowed_suffixes or normalised in seen:
                continue
            seen.add(normalised)
            filtered.append(normalised)
        return filtered
