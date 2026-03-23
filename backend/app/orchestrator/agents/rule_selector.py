"""Rule Selection Agent — choose targeted scanner rules for follow-up passes."""

import json
import logging
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
        target_files = result.get("target_files", [])

        # Resolve risk themes to directories
        for theme in risk_themes:
            if theme in RISK_THEME_DIRS:
                semgrep_dirs.extend(RISK_THEME_DIRS[theme])

        # Deduplicate
        semgrep_dirs = list(dict.fromkeys(semgrep_dirs))

        runs_done = 0

        # Targeted Semgrep
        if semgrep_dirs and "semgrep" in available and runs_done < budget:
            # Resolve to actual paths on disk
            rules_path = settings.semgrep_rules_path
            rule_paths = []
            for d in semgrep_dirs:
                full = rules_path / d
                if full.exists():
                    rule_paths.append(str(full))

            if rule_paths:
                labels = [d.split("/")[-1] for d in semgrep_dirs[:4]]
                ctx.current_task = f"Running targeted Semgrep ({', '.join(labels)})"
                await self.emit(ctx, f"Running targeted Semgrep: {', '.join(labels)} ({len(rule_paths)} rule dirs)")

                output = await available["semgrep"].run_targeted(
                    repo_path,
                    files=target_files or [],
                    rules=rule_paths,
                )

                if output.hits:
                    await self.emit(
                        ctx,
                        f"Targeted Semgrep found {len(output.hits)} additional hits",
                    )
                    ctx.scanner_hit_counts["semgrep_targeted"] = len(output.hits)
                    await self._persist_targeted_hits(ctx, "semgrep_targeted", output.hits, repo_path)

                runs_done += 1

        # Targeted Bandit
        if bandit_rules and "bandit" in available and "python" in ctx.languages and runs_done < budget:
            ctx.current_task = f"Running targeted Bandit ({', '.join(bandit_rules[:5])})"
            await self.emit(ctx, f"Running targeted Bandit: {', '.join(bandit_rules[:5])}")

            output = await available["bandit"].run_targeted(
                repo_path,
                files=target_files or [],
                rules=bandit_rules,
            )

            if output.hits:
                await self.emit(
                    ctx,
                    f"Targeted Bandit found {len(output.hits)} additional hits",
                )
                ctx.scanner_hit_counts["bandit_targeted"] = len(output.hits)
                await self._persist_targeted_hits(ctx, "bandit_targeted", output.hits, repo_path)

            runs_done += 1

        # Targeted ESLint
        if eslint_rules and "eslint" in available and any(
            l in ctx.languages for l in ("javascript", "typescript")
        ) and runs_done < budget:
            ctx.current_task = f"Running targeted ESLint ({', '.join(eslint_rules[:5])})"
            await self.emit(ctx, f"Running targeted ESLint: {', '.join(eslint_rules[:5])}")

            output = await available["eslint"].run_targeted(
                repo_path,
                files=target_files or [],
                rules=eslint_rules,
            )

            if output.hits:
                await self.emit(
                    ctx,
                    f"Targeted ESLint found {len(output.hits)} additional hits",
                )
                ctx.scanner_hit_counts["eslint_targeted"] = len(output.hits)
                await self._persist_targeted_hits(ctx, "eslint_targeted", output.hits, repo_path)

            runs_done += 1

        await self.emit(ctx, f"Targeted scanning complete. {runs_done} follow-up runs executed.")
        await self.emit_progress(ctx, task=f"Targeted scanning done — {runs_done} runs, {sum(v for k, v in ctx.scanner_hit_counts.items() if k.endswith('_targeted'))} new hits")

        await self.log_decision(
            ctx,
            action="rule_selection_complete",
            reasoning=result.get("reasoning", ""),
            output_summary=f"Selected {len(semgrep_dirs)} semgrep dirs, {len(bandit_rules)} bandit rules, {len(eslint_rules)} eslint rules",
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

        # Tell the AI what already ran in baseline so it doesn't repeat
        if ctx.baseline_rule_dirs:
            parts.append(f"\nAlready scanned in baseline (DO NOT re-select):")
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

        if "python" in ctx.languages:
            dirs.extend(["python/lang", "python/django", "python/flask", "python/fastapi"])
            themes.extend(["sqli", "command_injection", "deserialization"])
            bandit.extend(["B608", "B602", "B301", "B105"])

        eslint = []

        if any(l in ctx.languages for l in ("javascript", "typescript")):
            dirs.extend(["javascript/lang", "javascript/express", "javascript/browser"])
            themes.extend(["xss", "ssrf", "open_redirect", "nosql"])
            eslint.extend(["no-eval", "no-implied-eval", "no-new-func", "no-script-url", "no-proto"])

        if "java" in ctx.languages:
            dirs.extend(["java/lang", "java/spring", "java/servlets"])
            themes.extend(["xxe", "deserialization"])

        if "go" in ctx.languages:
            dirs.append("go")
            themes.extend(["sqli", "command_injection"])

        if "ruby" in ctx.languages:
            dirs.append("ruby")
            themes.extend(["sqli", "xss", "csrf"])

        if "php" in ctx.languages:
            dirs.append("php")
            themes.extend(["sqli", "xss", "deserialization"])

        # Always check secrets and generic
        dirs.append("generic")
        themes.extend(["hardcoded_secrets"])

        return {
            "semgrep_rule_dirs": list(dict.fromkeys(dirs)),
            "risk_themes": list(dict.fromkeys(themes)),
            "bandit_rules": list(set(bandit)),
            "eslint_rules": list(set(eslint)),
            "target_files": [],
            "reasoning": "Heuristic selection based on detected stack",
        }
