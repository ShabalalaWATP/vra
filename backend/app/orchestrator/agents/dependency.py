"""Dependency Risk Agent — assess dependency vulnerabilities with AI context."""

import logging

from sqlalchemy import select

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
      "relevance": "likely_used|unused|test_only|unknown",
      "assessment": "Brief explanation of why this dependency matters or doesn't",
      "risk_level": "critical|high|medium|low|info",
      "reasoning": "How you determined the relevance"
    }
  ]
}"""


class DependencyRiskAgent(BaseAgent):
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

    async def _find_import_usage(self, ctx: ScanContext, dep_findings: list) -> dict[str, list[str]]:
        """Find which files import the vulnerable packages."""
        usage: dict[str, list[str]] = {}

        # Get all file paths
        async with async_session() as session:
            result = await session.execute(
                select(File).where(File.scan_id == ctx.scan_id)
            )
            files = result.scalars().all()

        # For each vulnerable package, grep for imports
        package_names = set()
        for df, dep in dep_findings:
            package_names.add(dep.name)

        from pathlib import Path
        repo = Path(ctx.repo_path)

        for file_rec in files:
            if not file_rec.language:
                continue

            full_path = repo / file_rec.path
            if not full_path.exists():
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                content_lower = content.lower()

                for pkg in package_names:
                    pkg_lower = pkg.lower().replace("-", "_").replace(".", "/")
                    # Check various import patterns
                    if (
                        f"import {pkg_lower}" in content_lower
                        or f"from {pkg_lower}" in content_lower
                        or f"require('{pkg_lower}" in content_lower
                        or f'require("{pkg_lower}' in content_lower
                        or f"import '{pkg_lower}" in content_lower
                        or f'import "{pkg_lower}' in content_lower
                    ):
                        if pkg not in usage:
                            usage[pkg] = []
                        usage[pkg].append(file_rec.path)

            except Exception:
                continue

        return usage

    async def _assess_batch(
        self,
        ctx: ScanContext,
        batch: list,
        import_usage: dict[str, list[str]],
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
            pkg_files = import_usage.get(dep.name, [])
            parts.append(
                f"\n### {dep.name} v{dep.version} ({dep.ecosystem})"
                f"\n- Advisory: {df.advisory_id}"
                f"\n- Severity: {df.severity}"
                f"\n- Summary: {df.summary}"
                f"\n- Affected range: {df.affected_range}"
                f"\n- Fixed in: {df.fixed_version}"
                f"\n- Is dev dependency: {dep.is_dev}"
                f"\n- Source file: {dep.source_file}"
                f"\n- Files that import this package: {', '.join(pkg_files) if pkg_files else 'None found'}"
            )

            # Read a snippet from files that use this package
            if pkg_files and self.llm:
                for fp in pkg_files[:2]:
                    snippet = await self.read_file(ctx, fp, max_lines=50)
                    parts.append(f"\n**Usage in {fp}:**\n```\n{snippet[:500]}\n```")

        user_content = "\n".join(parts)

        if not self.llm:
            # No AI available — use heuristic
            await self._heuristic_assess(batch, import_usage)
            return

        try:
            result = await self.llm.chat_json(SYSTEM_PROMPT, user_content, max_tokens=2000)
            ctx.ai_calls_made += 1
        except Exception as e:
            await self.emit(ctx, f"Dependency assessment batch failed: {e}", level="warn")
            await self._heuristic_assess(batch, import_usage)
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
                            db_df.relevance = assessment.get("relevance", "unknown")
                            db_df.ai_assessment = assessment.get("assessment", "")
                        break

            await session.commit()

    async def _heuristic_assess(self, batch: list, import_usage: dict[str, list[str]]):
        """Heuristic assessment when AI is not available."""
        async with async_session() as session:
            for df, dep in batch:
                db_df = await session.get(DependencyFinding, df.id)
                if not db_df:
                    continue

                pkg_files = import_usage.get(dep.name, [])

                if dep.is_dev:
                    db_df.relevance = "test_only"
                    db_df.ai_assessment = "Dev dependency — not present in production builds."
                elif pkg_files:
                    db_df.relevance = "likely_used"
                    db_df.ai_assessment = f"Package imported in: {', '.join(pkg_files[:3])}"
                else:
                    db_df.relevance = "unknown"
                    db_df.ai_assessment = "No direct imports found; may be a transitive dependency."

            await session.commit()
