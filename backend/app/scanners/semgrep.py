"""Semgrep scanner adapter — runs Semgrep CLI with local offline rules.

Baseline scan: uses language-filtered rules from data/semgrep-rules/{lang}/
Targeted scan: uses specific rule paths selected by the rule_selector agent.
"""

import asyncio
import json
import shutil
import time
from tempfile import TemporaryDirectory
from pathlib import Path

import yaml

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

COMMON_MANIFEST_DIRS = ("", "backend", "frontend", "client", "server", "web", "api", "app")

FRAMEWORK_BASELINE_RULE_DIRS = {
    "django": ["python/django"],
    "flask": ["python/flask"],
    "fastapi": ["python/fastapi"],
    "sqlalchemy": ["python/sqlalchemy"],
    "express": ["javascript/express"],
    "react": ["javascript/browser", "javascript/react", "typescript/react"],
    "vue": ["javascript/browser", "javascript/vue"],
    "angular": ["javascript/browser", "javascript/angular", "typescript/angular"],
    "nextjs": ["javascript/browser", "javascript/react", "typescript/react"],
    "nuxtjs": ["javascript/browser", "javascript/vue"],
    "vite": ["javascript/browser"],
    "tailwind": ["javascript/browser"],
    "kubernetes": ["yaml/kubernetes"],
}

PACKAGE_BASELINE_RULE_DIRS = {
    "requests": ["python/requests"],
    "boto3": ["python/boto3"],
    "pymongo": ["python/pymongo"],
    "jinja2": ["python/jinja2"],
    "cryptography": ["python/cryptography"],
    "pycryptodome": ["python/pycryptodome"],
    "twilio": ["python/twilio"],
    "pyjwt": ["python/jwt"],
    "jwt": ["python/jwt"],
    "jsonwebtoken": ["javascript/jsonwebtoken"],
    "jose": ["javascript/jose"],
    "@nestjs/core": ["typescript/nestjs"],
    "@nestjs/common": ["typescript/nestjs"],
    "aws-cdk": ["typescript/aws-cdk"],
    "aws-cdk-lib": ["typescript/aws-cdk"],
}

JS_FRONTEND_SIGNALS = {"react", "vue", "angular", "nextjs", "nuxtjs", "vite", "tailwind", "svelte"}


class SemgrepAdapter(ScannerAdapter):
    def __init__(self):
        self._temp_dirs: list[TemporaryDirectory] = []
        self._prepared_config_labels: dict[str, str] = {}

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

    @staticmethod
    def _is_valid_top_level_config(config_path: Path) -> bool:
        """Validate the full YAML file so malformed bundled configs are skipped."""
        try:
            yaml.safe_load(config_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return False
        return True

    def _collect_valid_top_level_configs(self, lang_dir: Path) -> list[str]:
        configs: list[str] = []
        for top_yaml in sorted(list(lang_dir.glob("*.yaml")) + list(lang_dir.glob("*.yml"))):
            prepared = self._prepare_top_level_config(top_yaml)
            if prepared:
                configs.append(prepared)
        return configs

    @staticmethod
    def _sanitise_rule_file(config_path: Path) -> tuple[TemporaryDirectory, str] | str | None:
        """Drop known-bad bundled rules while keeping the rest of the config available."""
        try:
            raw_content = config_path.read_text(encoding="utf-8", errors="ignore")
            payload = yaml.safe_load(raw_content)
        except Exception:
            return None

        if not isinstance(payload, dict):
            return str(config_path)

        rules = payload.get("rules")
        if not isinstance(rules, list):
            return str(config_path)

        legacy_broken_nest_rule = (
            config_path.name == "security.yaml"
            and "typescript.nest.no-auth-guard" in raw_content
            and "@UseGuards(...)\n          ..." in raw_content
        )

        if not legacy_broken_nest_rule:
            return str(config_path)

        filtered_rules = [
            rule for rule in rules
            if isinstance(rule, dict) and rule.get("id") != "typescript.nest.no-auth-guard"
        ]
        if len(filtered_rules) == len(rules):
            return str(config_path)

        temp_dir = TemporaryDirectory(prefix="vragent-semgrep-")
        temp_path = Path(temp_dir.name) / config_path.name
        temp_path.write_text(
            yaml.safe_dump({"rules": filtered_rules}, sort_keys=False),
            encoding="utf-8",
        )
        return temp_dir, str(temp_path)

    def _prepare_top_level_config(self, config_path: Path) -> str | None:
        if not self._is_valid_top_level_config(config_path):
            return None

        prepared = self._sanitise_rule_file(config_path)
        if prepared is None:
            return None
        if isinstance(prepared, tuple):
            temp_dir, temp_path = prepared
            self._temp_dirs.append(temp_dir)
            self._prepared_config_labels[temp_path] = str(config_path)
            return temp_path
        return prepared

    @staticmethod
    def _candidate_manifest_paths(target_path: Path, manifest_name: str) -> list[Path]:
        candidates: list[Path] = []
        seen: set[Path] = set()
        for subdir in COMMON_MANIFEST_DIRS:
            base = target_path if not subdir else target_path / subdir
            candidate = base / manifest_name
            if candidate in seen or not candidate.exists() or not candidate.is_file():
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return candidates

    def _collect_package_signals(self, target_path: Path | None) -> set[str]:
        if target_path is None:
            return set()

        signals: set[str] = set()

        for package_json in self._candidate_manifest_paths(target_path, "package.json"):
            try:
                payload = json.loads(package_json.read_text(encoding="utf-8"))
            except Exception:
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                deps = payload.get(section, {})
                if isinstance(deps, dict):
                    signals.update(str(dep).lower() for dep in deps)

        tracked_python_packages = {
            key for key, value in PACKAGE_BASELINE_RULE_DIRS.items()
            if any(entry.startswith("python/") for entry in value)
        }
        tracked_python_packages.update({"django", "flask", "fastapi", "sqlalchemy"})
        for manifest_name in ("requirements.txt", "pyproject.toml", "poetry.lock"):
            for manifest in self._candidate_manifest_paths(target_path, manifest_name):
                try:
                    content = manifest.read_text(encoding="utf-8", errors="ignore").lower()
                except Exception:
                    continue
                for package in tracked_python_packages:
                    if package in content:
                        signals.add(package)

        return signals

    @staticmethod
    def _rule_dir_matches_languages(relative_path: str, languages: set[str]) -> bool:
        if not relative_path:
            return False
        head = relative_path.split("/", 1)[0]
        if head in {"dockerfile", "terraform", "yaml", "generic"}:
            return True
        if head == "javascript":
            return bool({"javascript", "typescript"} & languages)
        if head == "typescript":
            return "typescript" in languages
        mapped = LANG_TO_RULE_DIR.get(head, head)
        return mapped in languages or head in languages

    def _select_framework_rule_dirs(
        self,
        rules_path: Path,
        languages: list[str] | None,
        frameworks: list[str] | None,
        target_path: Path | None,
    ) -> list[str]:
        language_set = {lang.lower() for lang in (languages or [])}
        framework_signals = {fw.lower() for fw in (frameworks or [])}
        package_signals = self._collect_package_signals(target_path)
        configs: list[str] = []

        if {"javascript", "typescript"} & language_set and (framework_signals | package_signals) & JS_FRONTEND_SIGNALS:
            browser_dir = rules_path / "javascript" / "browser"
            if browser_dir.exists():
                configs.append(str(browser_dir))

        framework_like_signals = framework_signals | {
            signal for signal in package_signals
            if signal in FRAMEWORK_BASELINE_RULE_DIRS
        }

        for signal_source, mapping in (
            (framework_like_signals, FRAMEWORK_BASELINE_RULE_DIRS),
            (package_signals, PACKAGE_BASELINE_RULE_DIRS),
        ):
            for signal in sorted(signal_source):
                for relative_path in mapping.get(signal, []):
                    if not self._rule_dir_matches_languages(relative_path, language_set):
                        continue
                    candidate = rules_path / relative_path
                    if candidate.exists():
                        configs.append(str(candidate))

        return configs

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
        frameworks: list[str] | None = None,
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

        config_paths = self._get_baseline_configs(
            rules_path,
            languages,
            target_path,
            frameworks=frameworks,
        )

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
        *,
        frameworks: list[str] | None = None,
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

                configs.extend(self._collect_valid_top_level_configs(lang_dir))

            # JS and TS share core rules
            if "javascript" in languages:
                ts_lang = rules_path / "typescript" / "lang"
                if ts_lang.exists():
                    configs.append(str(ts_lang))
                configs.extend(self._collect_valid_top_level_configs(rules_path / "typescript"))
            if "typescript" in languages:
                js_lang = rules_path / "javascript" / "lang"
                if js_lang.exists():
                    configs.append(str(js_lang))
                configs.extend(self._collect_valid_top_level_configs(rules_path / "javascript"))

        configs.extend(self._select_framework_rule_dirs(rules_path, languages, frameworks, target_path))

        # Include infra rules ONLY if the repo contains those file types.
        # Use quick top-level checks instead of rglob (which is O(n) on huge repos).
        if target_path:
            common_dirs = (
                "backend", "frontend", "docker", "deploy", "infra", ".docker",
                "build", "api", "server", "client", "web", "app", "iac",
            )
            has_dockerfile = (target_path / "Dockerfile").exists() or (target_path / "dockerfile").exists()
            has_terraform = any(target_path.glob("*.tf")) or (target_path / "terraform").is_dir()
            has_compose = any(
                (target_path / name).exists()
                for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
            )
            has_github_actions = (target_path / ".github" / "workflows").is_dir()
            has_kubernetes = any((target_path / name).is_dir() for name in ("k8s", "kubernetes", "helm", "charts"))
            has_openapi = any(
                (target_path / name).exists()
                for name in ("openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml")
            )
            # If not found at root, do a shallow check (1 level deep only)
            if not has_dockerfile:
                has_dockerfile = any(
                    (target_path / d / "Dockerfile").exists()
                    for d in common_dirs
                    if (target_path / d).is_dir()
                )
            if not has_terraform:
                has_terraform = any(
                    any((target_path / d).glob("*.tf"))
                    for d in ("terraform", "infra", "deploy", "iac", "backend")
                    if (target_path / d).is_dir()
                )
            if not has_compose:
                has_compose = any(
                    any((target_path / d / name).exists() for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"))
                    for d in common_dirs
                    if (target_path / d).is_dir()
                )
            if not has_openapi:
                has_openapi = any(
                    any((target_path / d / name).exists() for name in ("openapi.yaml", "openapi.yml", "swagger.yaml", "swagger.yml"))
                    for d in common_dirs
                    if (target_path / d).is_dir()
                )
        else:
            has_dockerfile = True
            has_terraform = True
            has_compose = True
            has_github_actions = True
            has_kubernetes = True
            has_openapi = True

        if has_dockerfile:
            df_dir = rules_path / "dockerfile" / "security"
            if df_dir.exists():
                configs.append(str(df_dir))
            configs.extend(self._collect_valid_top_level_configs(rules_path / "dockerfile"))

        if has_terraform:
            tf_dir = rules_path / "terraform" / "lang"
            if tf_dir.exists():
                configs.append(str(tf_dir))
            configs.extend(self._collect_valid_top_level_configs(rules_path / "terraform"))

        if has_compose:
            yaml_dir = rules_path / "yaml" / "docker-compose"
            if yaml_dir.exists():
                configs.append(str(yaml_dir))
        if has_github_actions:
            yaml_dir = rules_path / "yaml" / "github-actions"
            if yaml_dir.exists():
                configs.append(str(yaml_dir))
        if has_kubernetes:
            yaml_dir = rules_path / "yaml" / "kubernetes"
            if yaml_dir.exists():
                configs.append(str(yaml_dir))
        if has_openapi:
            yaml_dir = rules_path / "yaml" / "openapi"
            if yaml_dir.exists():
                configs.append(str(yaml_dir))

        return list(dict.fromkeys(configs))

    def describe_config_paths(self, config_paths: list[str], *, rules_path: Path | None = None) -> list[str]:
        base = (rules_path or settings.semgrep_rules_path).resolve()
        labels: list[str] = []
        seen: set[str] = set()
        for config in config_paths:
            original = self._prepared_config_labels.get(config, config)
            try:
                label = str(Path(original).resolve().relative_to(base)).replace("\\", "/")
            except Exception:
                label = str(original).replace("\\", "/")
            if label in seen:
                continue
            seen.add(label)
            labels.append(label)
        return labels

    @staticmethod
    def _count_rules_in_path(config_path: Path) -> int:
        try:
            if config_path.is_dir():
                return sum(
                    SemgrepAdapter._count_rules_in_path(child)
                    for child in config_path.rglob("*")
                    if child.is_file() and child.suffix in {".yaml", ".yml"}
                )
            if config_path.is_file():
                return config_path.read_text(encoding="utf-8", errors="ignore").count("- id:")
        except Exception:
            return 0
        return 0

    def count_rules(self, config_paths: list[str]) -> int:
        return sum(self._count_rules_in_path(Path(config)) for config in config_paths)

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

    def cleanup(self):
        for temp_dir in self._temp_dirs:
            try:
                temp_dir.cleanup()
            except Exception:
                pass
        self._temp_dirs.clear()
