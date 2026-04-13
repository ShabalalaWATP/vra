"""ESLint scanner adapter — JS/TS security analysis."""

import asyncio
import json
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path

from app.analysis.paths import (
    load_repo_path_policy,
    normalise_path,
    relative_to_repo,
    should_skip_repo_path,
)
from app.config import settings
from app.scanners.base import ScannerAdapter, ScannerHit, ScannerOutput

SEVERITY_MAP = {
    2: "high",
    1: "medium",
    0: "info",
}

logger = logging.getLogger(__name__)


class ESLintAdapter(ScannerAdapter):
    TARGET_FILE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}

    @staticmethod
    def _detect_frontend_dir() -> Path:
        configured = os.environ.get("VRAGENT_FRONTEND_DIR")
        if configured:
            return Path(configured)

        current = Path(__file__).resolve()
        for parent in current.parents:
            candidate = parent / "frontend"
            if (candidate / "package.json").exists():
                return candidate

        container_candidate = Path("/frontend")
        if (container_candidate / "package.json").exists():
            return container_candidate

        return current.parents[3] / "frontend"

    def __init__(self) -> None:
        self._frontend_dir = self._detect_frontend_dir()
        self._bundled_node_modules = self._frontend_dir / "node_modules"
        self._install_attempted = False

    @staticmethod
    def _binary_candidates(base: str) -> list[str]:
        if os.name == "nt" and not Path(base).suffix:
            return [f"{base}{ext}" for ext in (".cmd", ".bat", ".exe", ".ps1", "")]
        return [base]

    def _local_binary_candidates(self) -> list[Path]:
        binary_name = Path(settings.eslint_binary).name
        bin_dir = self._bundled_node_modules / ".bin"
        return [bin_dir / candidate for candidate in self._binary_candidates(binary_name)]

    @staticmethod
    def _wrap_invocation(resolved: Path) -> list[str] | None:
        suffix = resolved.suffix.lower()
        if suffix == ".ps1":
            shell = shutil.which("pwsh") or shutil.which("powershell")
            if not shell:
                return None
            return [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(resolved)]
        if suffix in {".cmd", ".bat"}:
            shell = os.environ.get("COMSPEC") or shutil.which("cmd") or "cmd.exe"
            return [shell, "/c", str(resolved)]
        return [str(resolved)]

    @classmethod
    def _shell_invocation(cls, binary_name: str) -> list[str] | None:
        for candidate in cls._binary_candidates(binary_name):
            resolved = shutil.which(candidate)
            if resolved:
                return cls._wrap_invocation(Path(resolved))
        return None

    def _resolve_binary_path(self) -> Path | None:
        base = settings.eslint_binary

        explicit = Path(base)
        if explicit.exists():
            return explicit

        for candidate in self._local_binary_candidates():
            if candidate.exists():
                return candidate

        for candidate in self._binary_candidates(base):
            resolved = shutil.which(candidate)
            if resolved:
                return Path(resolved)

        return None

    def _resolve_invocation(self) -> list[str] | None:
        resolved = self._resolve_binary_path()
        if not resolved:
            return None
        return self._wrap_invocation(resolved)

    def _prepare_command(self, cmd: list[str]) -> list[str]:
        invocation = self._resolve_invocation()
        if not invocation:
            raise FileNotFoundError(f"ESLint binary not found: {settings.eslint_binary}")

        if cmd and cmd[0] == settings.eslint_binary:
            return [*invocation, *cmd[1:]]
        return cmd

    def _eslint_env(self) -> dict[str, str]:
        env = os.environ.copy()
        node_paths: list[str] = []
        existing = env.get("NODE_PATH", "")
        if existing:
            node_paths.extend(path for path in existing.split(os.pathsep) if path)
        if self._bundled_node_modules.exists():
            node_paths.append(str(self._bundled_node_modules))
        if node_paths:
            env["NODE_PATH"] = os.pathsep.join(dict.fromkeys(node_paths))
        return env

    async def _ensure_local_install(self) -> bool:
        if any(candidate.exists() for candidate in self._local_binary_candidates()):
            return True
        if self._install_attempted:
            return False

        self._install_attempted = True
        package_json = self._frontend_dir / "package.json"
        if not package_json.exists():
            return False

        npm_invocation = self._shell_invocation("npm")
        if not npm_invocation:
            logger.warning("Skipping local ESLint bootstrap because npm is not available on PATH.")
            return False

        install_modes = [["ci"], ["install"]] if (self._frontend_dir / "package-lock.json").exists() else [["install"]]
        last_error = ""

        for install_args in install_modes:
            cmd = [
                *npm_invocation,
                *install_args,
                "--include=dev",
                "--no-audit",
                "--no-fund",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=str(self._frontend_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=os.environ.copy(),
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            except asyncio.TimeoutError:
                logger.warning("Timed out while bootstrapping frontend dependencies for ESLint.")
                return False
            except Exception as exc:
                logger.warning("Failed to bootstrap frontend dependencies for ESLint: %s", exc)
                return False

            if proc.returncode == 0:
                return any(candidate.exists() for candidate in self._local_binary_candidates())

            stderr_text = stderr.decode(errors="replace").strip()
            stdout_text = stdout.decode(errors="replace").strip()
            last_error = stderr_text or stdout_text or f"exit code {proc.returncode}"
            if install_args[0] == "ci" and len(install_modes) > 1:
                logger.warning(
                    "npm ci failed while bootstrapping ESLint; retrying with npm install: %s",
                    last_error,
                )
                continue

            logger.warning(
                "npm %s failed while bootstrapping ESLint: %s",
                install_args[0],
                last_error,
            )
            return False

        if last_error:
            logger.warning("ESLint bootstrap failed: %s", last_error)
        return False

    @staticmethod
    def _flat_config_source(
        config_payload: dict,
        *,
        include_typescript: bool,
        warn_on_skipped_typescript: bool,
    ) -> tuple[str, list[str]]:
        warnings: list[str] = []
        parser_options = config_payload.get("parserOptions", {}) if isinstance(config_payload, dict) else {}
        base_files = ["**/*.{js,jsx,mjs,cjs,ts,tsx}"] if include_typescript else ["**/*.{js,jsx,mjs,cjs}"]
        base_payload = {
            "files": base_files,
            "languageOptions": {
                "ecmaVersion": parser_options.get("ecmaVersion", "latest"),
                "sourceType": parser_options.get("sourceType", "module"),
                "parserOptions": parser_options,
            },
            "rules": config_payload.get("rules", {}),
        }

        lines = ["const config = [];\n"]
        needs_ts_parser = any(
            isinstance(override, dict) and override.get("parser") == "@typescript-eslint/parser"
            for override in (config_payload.get("overrides", []) or [])
        )
        if include_typescript and needs_ts_parser:
            lines.append("const tsParser = require('@typescript-eslint/parser');\n")

        lines.append(f"config.push({json.dumps(base_payload, indent=2)});\n")

        for override in config_payload.get("overrides", []) or []:
            if not isinstance(override, dict):
                continue
            if (
                override.get("parser") == "@typescript-eslint/parser"
                and not include_typescript
                and warn_on_skipped_typescript
            ):
                warnings.append(
                    "TypeScript parser unavailable; ESLint fell back to JavaScript-only rules for this scan."
                )
                continue
            if override.get("parser") == "@typescript-eslint/parser" and not include_typescript:
                continue

            override_lines = ["config.push({\n"]
            if override.get("files"):
                override_lines.append(f"  files: {json.dumps(override.get('files'))},\n")
            language_options: dict = {}
            if override.get("parser") == "@typescript-eslint/parser":
                language_options["parser"] = "__TS_PARSER__"
            if override.get("parserOptions") is not None:
                language_options["parserOptions"] = override.get("parserOptions")
            if language_options:
                serialised = json.dumps(language_options, indent=2)
                serialised = serialised.replace('"__TS_PARSER__"', "tsParser")
                override_lines.append(f"  languageOptions: {serialised},\n")
            if override.get("rules") is not None:
                override_lines.append(f"  rules: {json.dumps(override.get('rules'), indent=2)}\n")
            override_lines.append("});\n")
            lines.extend(override_lines)

        lines.append("module.exports = config;\n")
        return "".join(lines), warnings

    @staticmethod
    def _strip_typescript_override(config_payload: dict) -> dict:
        config_copy = dict(config_payload)
        overrides = config_payload.get("overrides", [])
        if isinstance(overrides, list):
            cleaned = []
            for override in overrides:
                if (
                    isinstance(override, dict)
                    and override.get("parser") == "@typescript-eslint/parser"
                ):
                    continue
                cleaned.append(override)
            config_copy["overrides"] = cleaned
        return config_copy

    def _prepare_runtime_config(self, eslint_config: Path, *, include_typescript: bool) -> tuple[Path, list[str]]:
        return self._prepare_runtime_config_with_warnings(
            eslint_config,
            include_typescript=include_typescript,
            warn_on_skipped_typescript=True,
        )

    def _prepare_runtime_config_with_warnings(
        self,
        eslint_config: Path,
        *,
        include_typescript: bool,
        warn_on_skipped_typescript: bool,
    ) -> tuple[Path, list[str]]:
        try:
            config_payload = json.loads(eslint_config.read_text(encoding="utf-8"))
        except Exception:
            return eslint_config, []

        runtime_source, warnings = self._flat_config_source(
            config_payload,
            include_typescript=include_typescript,
            warn_on_skipped_typescript=warn_on_skipped_typescript,
        )
        temp_dir = Path(tempfile.mkdtemp(prefix="vragent-eslint-"))
        runtime_path = temp_dir / "security.cjs"
        runtime_path.write_text(runtime_source, encoding="utf-8")
        return runtime_path, warnings

    async def _typescript_parser_available(self, repo_root: Path) -> bool:
        candidates = [
            repo_root / "node_modules" / "@typescript-eslint" / "parser",
            repo_root / "frontend" / "node_modules" / "@typescript-eslint" / "parser",
            self._bundled_node_modules / "@typescript-eslint" / "parser",
        ]
        return any(candidate.exists() for candidate in candidates)

    @staticmethod
    def _wants_typescript(
        repo_root: Path,
        *,
        languages: list[str] | None = None,
        file_filter: list[str] | None = None,
    ) -> bool:
        if any((lang or "").strip().lower() == "typescript" for lang in (languages or [])):
            return True

        if any(Path(path).suffix.lower() in {".ts", ".tsx"} for path in (file_filter or [])):
            return True

        policy = load_repo_path_policy(repo_root)
        for pattern in ("*.ts", "*.tsx"):
            for candidate in repo_root.rglob(pattern):
                if not candidate.is_file():
                    continue
                if should_skip_repo_path(candidate, repo_root, policy=policy):
                    continue
                return True

        return False

    async def _base_command(
        self,
        *,
        repo_root: Path,
        languages: list[str] | None = None,
        file_filter: list[str] | None = None,
    ) -> tuple[list[str], list[str], Path]:
        if self._resolve_invocation() is None:
            await self._ensure_local_install()

        eslint_config = settings.data_dir / "eslint-configs" / "security.json"
        include_typescript = False
        if self._wants_typescript(repo_root, languages=languages, file_filter=file_filter):
            include_typescript = await self._typescript_parser_available(repo_root)
            if not include_typescript:
                await self._ensure_local_install()
                include_typescript = await self._typescript_parser_available(repo_root)
        warn_on_skipped_typescript = self._wants_typescript(
            repo_root,
            languages=languages,
            file_filter=file_filter,
        ) and not include_typescript

        runtime_config, warnings = self._prepare_runtime_config_with_warnings(
            eslint_config,
            include_typescript=include_typescript,
            warn_on_skipped_typescript=warn_on_skipped_typescript,
        )
        cmd = [
            settings.eslint_binary,
            "--format", "json",
            "--no-config-lookup",
            "--config", str(runtime_config),
        ]

        if file_filter:
            for f in file_filter:
                cmd.append(str(repo_root / f))

        return cmd, warnings, runtime_config

    @property
    def name(self) -> str:
        return "eslint"

    async def is_available(self) -> bool:
        if self._resolve_invocation() is not None:
            return True
        await self._ensure_local_install()
        return self._resolve_invocation() is not None

    async def get_version(self) -> str | None:
        try:
            invocation = self._resolve_invocation()
            if not invocation:
                if not await self._ensure_local_install():
                    return None
                invocation = self._resolve_invocation()
                if not invocation:
                    return None
            proc = await asyncio.create_subprocess_exec(
                *invocation, "--version",
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
        cmd, warnings, runtime_config = await self._base_command(
            repo_root=target_path,
            languages=languages,
            file_filter=file_filter,
        )

        try:
            if not file_filter:
                cmd.extend([
                    "--ext", ".js,.jsx,.ts,.tsx,.mjs,.cjs",
                    str(target_path),
                ])

            return await self._execute(cmd, repo_root=target_path, cwd=target_path, extra_warnings=warnings)
        finally:
            if runtime_config.parent.name.startswith("vragent-eslint-"):
                shutil.rmtree(runtime_config.parent, ignore_errors=True)

    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        safe_files: list[str] = []
        seen: set[str] = set()
        repo_root = target_path.resolve()

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
            if (
                not resolved.exists()
                or not resolved.is_file()
                or resolved.suffix.lower() not in self.TARGET_FILE_SUFFIXES
            ):
                continue
            rel_path = normalise_path(relative_to_repo(resolved, repo_root))
            if rel_path in seen:
                continue
            seen.add(rel_path)
            safe_files.append(rel_path)

        if not safe_files:
            return ScannerOutput(
                scanner_name=self.name,
                success=True,
                hits=[],
                duration_ms=0,
            )

        cmd, warnings, runtime_config = await self._base_command(
            repo_root=target_path,
            file_filter=safe_files,
        )

        try:
            if rules:
                for rule in rules:
                    cmd.extend(["--rule", f"{rule}: error"])

            for f in safe_files:
                cmd.append(str(target_path / f))

            return await self._execute(cmd, repo_root=target_path, cwd=target_path, extra_warnings=warnings)
        finally:
            if runtime_config.parent.name.startswith("vragent-eslint-"):
                shutil.rmtree(runtime_config.parent, ignore_errors=True)

    async def _execute(
        self,
        cmd: list[str],
        *,
        repo_root: Path | None = None,
        cwd: Path | None = None,
        timeout: int = 300,
        extra_warnings: list[str] | None = None,
    ) -> ScannerOutput:
        start = time.monotonic()
        try:
            cmd = self._prepare_command(cmd)
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=str(cwd) if cwd else None,
                env=self._eslint_env(),
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
                    errors=[*(extra_warnings or []), *([stderr.decode()] if stderr else [])],
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
                errors=list(extra_warnings or []),
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
