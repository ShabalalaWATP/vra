"""Bandit scanner adapter — Python-specific security analysis."""

import asyncio
import json
import shutil
import time
from pathlib import Path

from app.analysis.paths import normalise_path, relative_to_repo
from app.config import settings
from app.scanners.base import ScannerAdapter, ScannerHit, ScannerOutput

SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

CONFIDENCE_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


class BanditAdapter(ScannerAdapter):
    @staticmethod
    def _normalise_repo_files(target_path: Path, files: list[str]) -> list[str]:
        """Keep only files that resolve inside the scan target."""
        repo_root = target_path.resolve()
        safe_files: list[str] = []
        seen: set[str] = set()

        for file_path in files:
            if not file_path:
                continue
            raw = Path(file_path)
            candidate = raw if raw.is_absolute() else (target_path / raw)
            try:
                resolved = candidate.resolve()
                resolved.relative_to(repo_root)
            except (ValueError, OSError):
                continue
            if not resolved.exists() or not resolved.is_file():
                continue
            rel_path = normalise_path(relative_to_repo(resolved, repo_root))
            if rel_path in seen:
                continue
            seen.add(rel_path)
            safe_files.append(rel_path)

        return safe_files

    @property
    def name(self) -> str:
        return "bandit"

    async def is_available(self) -> bool:
        return shutil.which(settings.bandit_binary) is not None

    async def get_version(self) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.bandit_binary, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip().split("\n")[0]
        except Exception:
            return None

    async def run(
        self,
        target_path: Path,
        *,
        languages: list[str] | None = None,
        rules: list[str] | None = None,
        file_filter: list[str] | None = None,
    ) -> ScannerOutput:
        cmd = [
            settings.bandit_binary,
            "-r",
            "-f", "json",
            "--quiet",
        ]

        if rules:
            cmd.extend(["-t", ",".join(rules)])

        if file_filter:
            file_filter = self._normalise_repo_files(target_path, file_filter)
            if not file_filter:
                return ScannerOutput(
                    scanner_name=self.name,
                    success=False,
                    errors=["No valid repo files supplied to Bandit"],
                    duration_ms=0,
                )
            # Bandit can scan specific files
            cmd.extend(file_filter)
        else:
            cmd.append(str(target_path))

        return await self._execute(cmd, repo_root=target_path)

    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        cmd = [
            settings.bandit_binary,
            "-f", "json",
            "--quiet",
        ]
        if rules:
            cmd.extend(["-t", ",".join(rules)])

        safe_files = self._normalise_repo_files(target_path, files)
        if not safe_files:
            return ScannerOutput(
                scanner_name=self.name,
                success=False,
                errors=["No valid repo files supplied to Bandit"],
                duration_ms=0,
            )

        # Resolve files relative to target_path
        abs_files = [str(target_path / f) for f in safe_files]
        cmd.extend(abs_files)
        return await self._execute(cmd, repo_root=target_path)

    async def _execute(
        self, cmd: list[str], *, repo_root: Path | None = None, timeout: int = 300
    ) -> ScannerOutput:
        start = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                duration = int((time.monotonic() - start) * 1000)
                return ScannerOutput(
                    scanner_name=self.name, success=False,
                    errors=[f"Bandit timed out after {timeout}s"], duration_ms=duration,
                )
            duration = int((time.monotonic() - start) * 1000)

            if not stdout:
                return ScannerOutput(
                    scanner_name=self.name,
                    success=proc.returncode in (0, 1),  # 1 = findings found
                    errors=[stderr.decode()] if stderr else [],
                    duration_ms=duration,
                )

            data = json.loads(stdout.decode())
            hits = []
            for result in data.get("results", []):
                raw_path = result.get("filename", "")
                try:
                    file_path = (
                        normalise_path(relative_to_repo(Path(raw_path), repo_root))
                        if repo_root
                        else normalise_path(raw_path)
                    )
                except Exception:
                    file_path = normalise_path(raw_path)
                hits.append(
                    ScannerHit(
                        rule_id=result.get("test_id", "unknown"),
                        severity=SEVERITY_MAP.get(
                            result.get("issue_severity", "LOW"), "low"
                        ),
                        message=result.get("issue_text", ""),
                        file_path=file_path,
                        start_line=result.get("line_number", 0),
                        end_line=result.get("line_range", [0, 0])[-1] or None,
                        snippet=result.get("code", ""),
                        metadata={
                            "confidence": result.get("issue_confidence", ""),
                            "test_name": result.get("test_name", ""),
                            "cwe": result.get("issue_cwe", {}),
                        },
                    )
                )

            return ScannerOutput(
                scanner_name=self.name,
                success=True,
                hits=hits,
                duration_ms=duration,
            )
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            return ScannerOutput(
                scanner_name=self.name,
                success=False,
                errors=[str(e)],
                duration_ms=duration,
            )
