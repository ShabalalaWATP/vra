"""Tests for scanner adapter command resolution and config validation."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

from app.config import settings
from app.scanners.eslint import ESLintAdapter
from app.scanners.semgrep import SemgrepAdapter


def test_eslint_prefers_cmd_wrapper_on_windows(tmp_path):
    adapter = ESLintAdapter()
    adapter._frontend_dir = tmp_path / "frontend"
    adapter._bundled_node_modules = adapter._frontend_dir / "node_modules"

    def which(name: str) -> str | None:
        mapping = {
            "eslint.cmd": r"C:\Tools\eslint.cmd",
            "eslint": r"C:\Tools\eslint.ps1",
        }
        return mapping.get(name)

    with patch("app.scanners.eslint.os.name", "nt"), patch(
        "app.scanners.eslint.shutil.which", side_effect=which
    ):
        assert adapter._resolve_binary_path() == Path(r"C:\Tools\eslint.cmd")


def test_eslint_wraps_powershell_launchers(tmp_path):
    adapter = ESLintAdapter()
    adapter._frontend_dir = tmp_path / "frontend"
    adapter._bundled_node_modules = adapter._frontend_dir / "node_modules"

    def which(name: str) -> str | None:
        mapping = {
            "eslint.ps1": r"C:\Tools\eslint.ps1",
            "pwsh": r"C:\Program Files\PowerShell\7\pwsh.exe",
        }
        return mapping.get(name)

    with patch("app.scanners.eslint.os.name", "nt"), patch(
        "app.scanners.eslint.shutil.which", side_effect=which
    ):
        invocation = adapter._resolve_invocation()

    assert invocation == [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        r"C:\Tools\eslint.ps1",
    ]


def test_eslint_prefers_repo_local_binary_over_path(tmp_path):
    adapter = ESLintAdapter()
    adapter._frontend_dir = tmp_path / "frontend"
    adapter._bundled_node_modules = adapter._frontend_dir / "node_modules"
    local_binary = adapter._bundled_node_modules / ".bin" / "eslint"
    local_binary.parent.mkdir(parents=True)
    local_binary.write_text("", encoding="utf-8")

    with patch("app.scanners.eslint.os.name", "posix"), patch(
        "app.scanners.eslint.shutil.which",
        return_value="/usr/bin/eslint",
    ):
        assert adapter._resolve_binary_path() == local_binary


def test_eslint_is_available_bootstraps_local_install(tmp_path):
    adapter = ESLintAdapter()
    adapter._frontend_dir = tmp_path / "frontend"
    adapter._bundled_node_modules = adapter._frontend_dir / "node_modules"
    adapter._frontend_dir.mkdir(parents=True)
    (adapter._frontend_dir / "package.json").write_text("{}", encoding="utf-8")
    (adapter._frontend_dir / "package-lock.json").write_text("{}", encoding="utf-8")
    local_binary = adapter._bundled_node_modules / ".bin" / "eslint"
    spawned: dict[str, tuple[str, ...] | str] = {}

    class FakeProc:
        returncode = 0

        async def communicate(self):
            local_binary.parent.mkdir(parents=True, exist_ok=True)
            local_binary.write_text("", encoding="utf-8")
            return b"", b""

    async def fake_exec(*cmd, **kwargs):
        spawned["cmd"] = tuple(cmd)
        spawned["cwd"] = kwargs.get("cwd", "")
        return FakeProc()

    with patch("app.scanners.eslint.os.name", "posix"), patch(
        "app.scanners.eslint.shutil.which",
        return_value=None,
    ), patch.object(
        ESLintAdapter,
        "_shell_invocation",
        return_value=["npm"],
    ), patch(
        "app.scanners.eslint.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        assert asyncio.run(adapter.is_available()) is True

    assert spawned["cmd"][:2] == ("npm", "ci")
    assert spawned["cwd"] == str(adapter._frontend_dir)


def test_eslint_bootstrap_falls_back_to_npm_install_when_ci_fails(tmp_path):
    adapter = ESLintAdapter()
    adapter._frontend_dir = tmp_path / "frontend"
    adapter._bundled_node_modules = adapter._frontend_dir / "node_modules"
    adapter._frontend_dir.mkdir(parents=True)
    (adapter._frontend_dir / "package.json").write_text("{}", encoding="utf-8")
    (adapter._frontend_dir / "package-lock.json").write_text("{}", encoding="utf-8")
    local_binary = adapter._bundled_node_modules / ".bin" / "eslint"
    spawned: list[tuple[str, ...]] = []

    class FakeProc:
        def __init__(self, returncode: int, create_binary: bool = False):
            self.returncode = returncode
            self._create_binary = create_binary

        async def communicate(self):
            if self._create_binary:
                local_binary.parent.mkdir(parents=True, exist_ok=True)
                local_binary.write_text("", encoding="utf-8")
            return b"", b"lock mismatch" if self.returncode else b""

    async def fake_exec(*cmd, **kwargs):
        spawned.append(tuple(cmd))
        return FakeProc(1, False) if len(spawned) == 1 else FakeProc(0, True)

    with patch("app.scanners.eslint.os.name", "posix"), patch(
        "app.scanners.eslint.shutil.which",
        return_value=None,
    ), patch.object(
        ESLintAdapter,
        "_shell_invocation",
        return_value=["npm"],
    ), patch(
        "app.scanners.eslint.asyncio.create_subprocess_exec",
        side_effect=fake_exec,
    ):
        assert asyncio.run(adapter.is_available()) is True

    assert spawned[0][:2] == ("npm", "ci")
    assert spawned[1][:2] == ("npm", "install")


def test_semgrep_filters_top_level_configs_using_full_file_validation(tmp_path):
    adapter = SemgrepAdapter()
    rules_dir = tmp_path / "python"
    rules_dir.mkdir()

    valid = rules_dir / "security.yaml"
    valid.write_text(
        "rules:\n"
        "  - id: python-safe-example\n"
        "    message: safe example\n"
        "    severity: ERROR\n"
        "    languages: [python]\n"
        "    pattern: subprocess.run(...)\n",
        encoding="utf-8",
    )

    invalid = rules_dir / "frameworks.yaml"
    invalid.write_text(
        "rules:\n"
        + ("# filler to push the syntax error past 5KB\n" * 220)
        + "  - id: broken-rule\n"
        + "    message: broken\n"
        + "    severity: ERROR\n"
        + "    languages: [python]\n"
        + "    pattern: [\n",
        encoding="utf-8",
    )

    configs = adapter._collect_valid_top_level_configs(rules_dir)

    assert str(valid) in configs
    assert str(invalid) not in configs


def test_eslint_runtime_config_strips_typescript_override_when_parser_missing(tmp_path):
    adapter = ESLintAdapter()
    config_path = tmp_path / "security.json"
    config_path.write_text(
        json.dumps(
            {
                "rules": {"no-eval": "error"},
                "overrides": [
                    {"files": ["*.ts"], "parser": "@typescript-eslint/parser", "rules": {}}
                ],
            }
        ),
        encoding="utf-8",
    )

    runtime_config, warnings = adapter._prepare_runtime_config(
        config_path,
        include_typescript=False,
    )
    payload = runtime_config.read_text(encoding="utf-8")

    assert '"no-eval": "error"' in payload
    assert "@typescript-eslint/parser" not in payload
    assert warnings


def test_eslint_runtime_config_keeps_typescript_override_when_parser_available(tmp_path):
    adapter = ESLintAdapter()
    config_path = tmp_path / "security.json"
    config_path.write_text(
        json.dumps(
            {
                "rules": {"no-eval": "error"},
                "overrides": [
                    {
                        "files": ["**/*.{ts,tsx}"],
                        "parser": "@typescript-eslint/parser",
                        "parserOptions": {"ecmaVersion": "latest", "sourceType": "module"},
                        "rules": {"no-warning-comments": ["warn", {"terms": ["@ts-ignore"], "location": "anywhere"}]},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    runtime_config, warnings = adapter._prepare_runtime_config(
        config_path,
        include_typescript=True,
    )
    payload = runtime_config.read_text(encoding="utf-8")

    assert "require('@typescript-eslint/parser')" in payload
    assert '"**/*.{ts,tsx}"' in payload
    assert '"@ts-ignore"' in payload
    assert "tsParser" in payload
    assert not warnings


def test_eslint_base_command_bootstraps_typescript_parser_when_needed(tmp_path):
    adapter = ESLintAdapter()
    adapter._frontend_dir = tmp_path / "frontend"
    adapter._bundled_node_modules = adapter._frontend_dir / "node_modules"
    adapter._frontend_dir.mkdir(parents=True)
    (adapter._frontend_dir / "package.json").write_text("{}", encoding="utf-8")

    with patch.object(adapter, "_resolve_invocation", return_value=["eslint"]), patch.object(
        adapter,
        "_ensure_local_install",
        AsyncMock(return_value=True),
    ) as ensure_mock, patch.object(
        adapter,
        "_typescript_parser_available",
        AsyncMock(side_effect=[False, True]),
    ):
        cmd, warnings, runtime_config = asyncio.run(
            adapter._base_command(repo_root=tmp_path, languages=["typescript"])
        )

    payload = runtime_config.read_text(encoding="utf-8")

    assert ensure_mock.await_count == 1
    assert "tsParser" in payload
    assert not warnings
    assert "--config" in cmd


def test_eslint_project_security_config_is_material_and_typescript_aware():
    config_path = settings.data_dir / "eslint-configs" / "security.json"
    payload = json.loads(config_path.read_text(encoding="utf-8"))

    assert len(payload.get("rules", {})) >= 40
    overrides = payload.get("overrides", [])
    assert overrides
    ts_override = overrides[0]
    assert ts_override["parser"] == "@typescript-eslint/parser"
    assert ts_override["files"] == ["**/*.{ts,tsx}"]
    assert ts_override["rules"]


def test_semgrep_sanitises_legacy_broken_nest_rule(tmp_path):
    adapter = SemgrepAdapter()
    config_path = tmp_path / "security.yaml"
    config_path.write_text(
        "rules:\n"
        "  - id: typescript.nest.no-auth-guard\n"
        "    patterns:\n"
        "      - pattern: |\n"
        "          @Controller(...)\n"
        "          class $CLASS {\n"
        "            @Get(...)\n"
        "            $METHOD(...) { ... }\n"
        "          }\n"
        "      - pattern-not-inside: |\n"
        "          @UseGuards(...)\n"
        "          ...\n",
        encoding="utf-8",
    )

    prepared = adapter._prepare_top_level_config(config_path)

    assert prepared is not None
    assert Path(prepared) != config_path
    assert "typescript.nest.no-auth-guard" not in Path(prepared).read_text(encoding="utf-8")


def test_semgrep_keeps_fixed_nest_rule(tmp_path):
    adapter = SemgrepAdapter()
    config_path = tmp_path / "security.yaml"
    config_path.write_text(
        "rules:\n"
        "  - id: typescript.nest.no-auth-guard\n"
        "    patterns:\n"
        "      - pattern-inside: |\n"
        "          @Controller(...)\n"
        "          class $CLASS {\n"
        "            ...\n"
        "          }\n"
        "      - pattern: |\n"
        "          @Get(...)\n"
        "          $METHOD(...) { ... }\n"
        "      - pattern-not-inside: |\n"
        "          @UseGuards(...)\n"
        "          $METHOD(...) { ... }\n",
        encoding="utf-8",
    )

    prepared = adapter._prepare_top_level_config(config_path)

    assert prepared == str(config_path)


def test_semgrep_project_top_level_security_configs_are_loadable():
    adapter = SemgrepAdapter()
    rules_root = settings.semgrep_rules_path

    expected = {
        str(rules_root / "python" / "security.yaml"),
        str(rules_root / "javascript" / "frameworks.yaml"),
        str(rules_root / "javascript" / "security.yaml"),
    }

    collected = set(adapter._collect_valid_top_level_configs(rules_root / "python"))
    collected.update(adapter._collect_valid_top_level_configs(rules_root / "javascript"))

    assert expected.issubset(collected)


def test_semgrep_baseline_promotes_framework_and_infra_dirs(tmp_path):
    adapter = SemgrepAdapter()
    rules_root = tmp_path / "rules"
    repo_root = tmp_path / "repo"

    def write_rule(path: Path, *, language: str = "python", pattern: str = "print(...)"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "rules:\n"
            f"  - id: {path.stem}-rule\n"
            "    message: test rule\n"
            "    severity: ERROR\n"
            f"    languages: [{language}]\n"
            f"    pattern: {pattern}\n",
            encoding="utf-8",
        )

    write_rule(rules_root / "python" / "lang" / "core.yaml")
    write_rule(rules_root / "python" / "django" / "framework.yaml")
    write_rule(rules_root / "javascript" / "lang" / "core.yaml", language="javascript", pattern="console.log(...)")
    write_rule(rules_root / "javascript" / "browser" / "dom.yaml", language="javascript", pattern="document.write(...)")
    write_rule(rules_root / "typescript" / "lang" / "core.yaml", language="typescript", pattern="console.log(...)")
    write_rule(rules_root / "typescript" / "react" / "jsx.yaml", language="typescript", pattern="console.log(...)")
    write_rule(rules_root / "dockerfile" / "security" / "root-user.yaml", language="dockerfile", pattern="FROM ...")
    write_rule(rules_root / "dockerfile" / "security.yaml", language="dockerfile", pattern="FROM ...")
    write_rule(rules_root / "yaml" / "docker-compose" / "compose.yaml", language="yaml", pattern="services: ...")
    write_rule(rules_root / "yaml" / "github-actions" / "gha.yaml", language="yaml", pattern="jobs: ...")

    (repo_root / "backend").mkdir(parents=True)
    (repo_root / "backend" / "Dockerfile").write_text("FROM python:3.12\n", encoding="utf-8")
    (repo_root / ".github" / "workflows").mkdir(parents=True)
    (repo_root / ".github" / "workflows" / "ci.yml").write_text("name: ci\n", encoding="utf-8")
    (repo_root / "docker-compose.yml").write_text("services:\n  app:\n    build: .\n", encoding="utf-8")
    (repo_root / "frontend").mkdir(parents=True, exist_ok=True)
    (repo_root / "frontend" / "package.json").write_text(
        json.dumps({"dependencies": {"react": "^19.0.0"}}),
        encoding="utf-8",
    )

    configs = adapter._get_baseline_configs(
        rules_root,
        ["python", "typescript"],
        repo_root,
        frameworks=["django", "vite"],
    )
    labels = set(adapter.describe_config_paths(configs, rules_path=rules_root))

    assert "python/lang" in labels
    assert "python/django" in labels
    assert "javascript/browser" in labels
    assert "typescript/react" in labels
    assert "dockerfile/security" in labels
    assert "dockerfile/security.yaml" in labels
    assert "yaml/docker-compose" in labels
    assert "yaml/github-actions" in labels
