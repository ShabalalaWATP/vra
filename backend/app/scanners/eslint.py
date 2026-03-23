"""ESLint scanner adapter — JS/TS security analysis."""

import asyncio
import json
import shutil
import time
from pathlib import Path

from app.analysis.paths import normalise_path, relative_to_repo
from app.config import settings
from app.scanners.base import ScannerAdapter, ScannerHit, ScannerOutput

SEVERITY_MAP = {
    2: "high",
    1: "medium",
    0: "info",
}


class ESLintAdapter(ScannerAdapter):
    @property
    def name(self) -> str:
        return "eslint"

    async def is_available(self) -> bool:
        return shutil.which(settings.eslint_binary) is not None

    async def get_version(self) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.eslint_binary, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            return stdout.decode().strip()
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
        eslint_config = settings.data_dir / "eslint-configs" / "security.json"
        cmd = [
            settings.eslint_binary,
            "--format", "json",
            "--no-eslintrc",
        ]

        if eslint_config.exists():
            cmd.extend(["--config", str(eslint_config)])

        if file_filter:
            for f in file_filter:
                cmd.append(str(target_path / f))
        else:
            cmd.extend([
                "--ext", ".js,.jsx,.ts,.tsx,.mjs,.cjs",
                str(target_path),
            ])

        return await self._execute(cmd, repo_root=target_path)

    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        eslint_config = settings.data_dir / "eslint-configs" / "security.json"
        cmd = [
            settings.eslint_binary,
            "--format", "json",
            "--no-eslintrc",
        ]

        if eslint_config.exists():
            cmd.extend(["--config", str(eslint_config)])

        if rules:
            for rule in rules:
                cmd.extend(["--rule", f"{rule}: error"])

        for f in files:
            cmd.append(str(target_path / f))

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
                    errors=[f"ESLint timed out after {timeout}s"], duration_ms=duration,
                )
            duration = int((time.monotonic() - start) * 1000)

            if not stdout:
                return ScannerOutput(
                    scanner_name=self.name,
                    success=proc.returncode in (0, 1),
                    errors=[stderr.decode()] if stderr else [],
                    duration_ms=duration,
                )

            data = json.loads(stdout.decode())
            hits = []
            for file_result in data:
                raw_path = file_result.get("filePath", "")
                try:
                    file_path = (
                        normalise_path(relative_to_repo(Path(raw_path), repo_root))
                        if repo_root
                        else normalise_path(raw_path)
                    )
                except Exception:
                    file_path = normalise_path(raw_path)
                for msg in file_result.get("messages", []):
                    hits.append(
                        ScannerHit(
                            rule_id=msg.get("ruleId", "unknown") or "parse-error",
                            severity=SEVERITY_MAP.get(msg.get("severity", 0), "info"),
                            message=msg.get("message", ""),
                            file_path=file_path,
                            start_line=msg.get("line", 0),
                            end_line=msg.get("endLine"),
                            snippet=msg.get("source", ""),
                            metadata={
                                "node_type": msg.get("nodeType", ""),
                                "fatal": msg.get("fatal", False),
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
