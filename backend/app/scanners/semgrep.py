"""Semgrep scanner adapter — runs Semgrep CLI with local offline rules.

Baseline scan: uses language-filtered rules from data/semgrep-rules/{lang}/
Targeted scan: uses specific rule paths selected by the rule_selector agent.
"""

import asyncio
import json
import shutil
import time
from pathlib import Path

from app.analysis.paths import normalise_path, relative_to_repo
from app.config import settings
from app.scanners.base import ScannerAdapter, ScannerHit, ScannerOutput

SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

# Map fingerprint language names to semgrep rule directory names
LANG_TO_RULE_DIR = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "go": "go",
    "ruby": "ruby",
    "php": "php",
    "csharp": "csharp",
    "c": "c",
    "kotlin": "kotlin",
    "rust": "rust",
    "scala": "scala",
    "swift": "swift",
}


class SemgrepAdapter(ScannerAdapter):
    @staticmethod
    def _normalise_repo_files(target_path: Path, files: list[str]) -> list[str]:
        """Keep only repo-local files and return normalised relative paths."""
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
        return "semgrep"

    async def is_available(self) -> bool:
        return shutil.which(settings.semgrep_binary) is not None

    async def get_version(self) -> str | None:
        try:
            proc = await asyncio.create_subprocess_exec(
                settings.semgrep_binary, "--version",
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
        """
        Run baseline Semgrep scan.

        Instead of loading ALL 2000+ rules (slow, noisy), loads only the
        rule directories relevant to the detected languages, plus generic rules.
        """
        rules_path = settings.semgrep_rules_path
        if not rules_path.exists():
            return ScannerOutput(
                scanner_name=self.name,
                success=False,
                errors=[
                    f"Semgrep rules directory not found: {rules_path}. "
                    f"Run 'python -m scripts.download_semgrep_rules' to download rules."
                ],
                duration_ms=0,
            )

        config_paths = self._get_baseline_configs(rules_path, languages, target_path)

        if not config_paths:
            config_paths = [str(rules_path)]

        cmd = [
            settings.semgrep_binary,
            "scan",
            "--json",
            "--no-git-ignore",
            "--metrics", "off",
            "--quiet",
        ]

        for config in config_paths:
            # Semgrep's Go binary requires forward-slash paths on Windows
            cmd.extend(["--config", config.replace("\\", "/")])

        if file_filter:
            file_filter = self._normalise_repo_files(target_path, file_filter)
            if not file_filter:
                return ScannerOutput(
                    scanner_name=self.name,
                    success=False,
                    errors=["No valid repo files supplied to Semgrep"],
                    duration_ms=0,
                )
            for f in file_filter:
                cmd.extend(["--include", f])

        cmd.append(str(target_path).replace("\\", "/"))
        return await self._execute(cmd)

    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        """Run targeted Semgrep with specific rules on specific files."""
        cmd = [
            settings.semgrep_binary,
            "scan",
            "--json",
            "--no-git-ignore",
            "--metrics", "off",
            "--quiet",
        ]

        rules_path = settings.semgrep_rules_path

        for rule in rules:
            resolved = self._resolve_rule_path(rule, rules_path)
            if resolved:
                cmd.extend(["--config", resolved.replace("\\", "/")])

        if "--config" not in cmd:
            cmd.extend(["--config", str(rules_path).replace("\\", "/")])

        safe_files = self._normalise_repo_files(target_path, files)
        if not safe_files:
            return ScannerOutput(
                scanner_name=self.name,
                success=False,
                errors=["No valid repo files supplied to Semgrep"],
                duration_ms=0,
            )

        for f in safe_files:
            cmd.extend(["--include", f])

        cmd.append(str(target_path).replace("\\", "/"))
        return await self._execute(cmd)

    def _get_baseline_configs(
        self, rules_path: Path, languages: list[str] | None,
        target_path: Path | None = None,
    ) -> list[str]:
        """
        Get the Semgrep --config paths for a LEAN baseline scan.

        Strategy:
        - Load only the `lang/lang` and `lang/security.yaml` core rules for
          each detected language. NOT the full framework-specific subdirectories
          like python/django, python/flask etc. — those are saved for targeted scans.
        - Load generic rules (secrets, hardcoded keys).
        - Load infra rules ONLY if the repo actually contains those file types.

        This keeps the baseline fast and focused. The rule_selector agent
        later runs framework-specific rules (python/django, javascript/express,
        java/spring) as targeted follow-ups on files the investigator flagged.
        """
        configs = []

        if not rules_path.exists():
            return configs

        # NOTE: generic/ rules are skipped in baseline — they cause semgrep to
        # crash on Windows (empty stdout) and overlap with the dedicated secrets
        # scanner. They can still be loaded via targeted scans if needed.

        # Add core language rules — ONLY the lang/ subdirectory and top-level .yaml files,
        # not the framework-specific subdirs (those come in targeted passes)
        if languages:
            for lang in languages:
                rule_dir_name = LANG_TO_RULE_DIR.get(lang)
                if not rule_dir_name:
                    continue
                lang_dir = rules_path / rule_dir_name
                if not lang_dir.exists():
                    continue

                # Include the lang/ core subdirectory (e.g., python/lang/)
                lang_core = lang_dir / "lang"
                if lang_core.exists():
                    configs.append(str(lang_core))

                # Include top-level yaml files in the language dir
                # but validate them first (malformed YAML causes semgrep to skip everything)
                for top_yaml in list(lang_dir.glob("*.yaml")) + list(lang_dir.glob("*.yml")):
                    try:
                        import yaml
                        yaml.safe_load(top_yaml.read_text(encoding="utf-8", errors="ignore")[:5000])
                        configs.append(str(top_yaml))
                    except Exception:
                        pass  # Skip malformed YAML files

            # JS and TS share core rules
            if "javascript" in languages:
                ts_lang = rules_path / "typescript" / "lang"
                if ts_lang.exists():
                    configs.append(str(ts_lang))
                for top_yaml in list((rules_path / "typescript").glob("*.yaml")) + list((rules_path / "typescript").glob("*.yml")):
                    configs.append(str(top_yaml))
            if "typescript" in languages:
                js_lang = rules_path / "javascript" / "lang"
                if js_lang.exists():
                    configs.append(str(js_lang))
                for top_yaml in (rules_path / "javascript").glob("*.yaml"):
                    configs.append(str(top_yaml))

        # Include infra rules ONLY if the repo contains those file types.
        # Use quick top-level checks instead of rglob (which is O(n) on huge repos).
        if target_path:
            has_dockerfile = (target_path / "Dockerfile").exists() or (target_path / "dockerfile").exists()
            has_terraform = any(target_path.glob("*.tf")) or (target_path / "terraform").is_dir()
            has_yaml_configs = (target_path / ".github").is_dir() or any(target_path.glob("*.yaml"))
            # If not found at root, do a shallow check (1 level deep only)
            if not has_dockerfile:
                has_dockerfile = any(
                    (target_path / d / "Dockerfile").exists()
                    for d in ("docker", "deploy", "infra", ".docker", "build")
                    if (target_path / d).is_dir()
                )
            if not has_terraform:
                has_terraform = any(
                    any((target_path / d).glob("*.tf"))
                    for d in ("terraform", "infra", "deploy", "iac")
                    if (target_path / d).is_dir()
                )
        else:
            has_dockerfile = True
            has_terraform = True
            has_yaml_configs = True

        if has_dockerfile:
            df_dir = rules_path / "dockerfile"
            if df_dir.exists():
                configs.append(str(df_dir))

        if has_terraform:
            tf_dir = rules_path / "terraform"
            if tf_dir.exists():
                configs.append(str(tf_dir))

        if has_yaml_configs:
            yaml_dir = rules_path / "yaml"
            if yaml_dir.exists():
                configs.append(str(yaml_dir))

        return list(dict.fromkeys(configs))

    def _resolve_rule_path(self, rule: str, rules_path: Path) -> str | None:
        """
        Resolve a rule reference to an actual path.

        Handles:
        - Absolute paths: /full/path/to/rule.yaml
        - Relative paths: python/django/security.yaml
        - Directory paths: python/django, java/spring
        - Category shorthand: sqli, xss, command_injection
        """
        p = Path(rule)
        if p.is_absolute() and p.exists():
            return str(p)

        # Relative path under rules_path
        relative = rules_path / rule
        if relative.exists():
            return str(relative)

        # Try as language/subdirectory (e.g., "python/django")
        if "/" in rule:
            parts = rule.split("/")
            candidate = rules_path / parts[0]
            for part in parts[1:]:
                candidate = candidate / part
            if candidate.exists():
                return str(candidate)

        # Search for directories matching at any level
        for match in rules_path.rglob("*"):
            if match.is_dir() and match.name == rule:
                return str(match)

        # Search for files containing the rule name
        rule_clean = rule.replace("/", "-").replace("_", "-").lower()
        for yaml_file in rules_path.rglob("*.yaml"):
            rel = str(yaml_file.relative_to(rules_path)).replace("\\", "/").replace("_", "-").lower()
            if rule_clean in rel:
                return str(yaml_file)

        return None

    async def _execute(self, cmd: list[str], timeout: int = 600) -> ScannerOutput:
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
                    errors=[f"Semgrep timed out after {timeout}s"], duration_ms=duration,
                )
            duration = int((time.monotonic() - start) * 1000)

            if not stdout:
                return ScannerOutput(
                    scanner_name=self.name,
                    success=proc.returncode in (0, 1),
                    errors=[stderr.decode()[:500]] if stderr else [],
                    duration_ms=duration,
                )

            data = json.loads(stdout.decode())
            hits = []
            for result in data.get("results", []):
                hits.append(
                    ScannerHit(
                        rule_id=result.get("check_id", "unknown"),
                        severity=SEVERITY_MAP.get(
                            result.get("extra", {}).get("severity", "INFO"), "low"
                        ),
                        message=result.get("extra", {}).get("message", ""),
                        file_path=result.get("path", ""),
                        start_line=result.get("start", {}).get("line", 0),
                        end_line=result.get("end", {}).get("line"),
                        snippet=result.get("extra", {}).get("lines", ""),
                        metadata=result.get("extra", {}).get("metadata", {}),
                    )
                )

            errors = [e.get("message", "") for e in data.get("errors", [])]
            return ScannerOutput(
                scanner_name=self.name,
                success=True,
                hits=hits,
                errors=errors,
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
