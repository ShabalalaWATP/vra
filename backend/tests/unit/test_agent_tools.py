"""Tests for agent tool safety and taint-flow metadata exposure."""

import asyncio
import uuid
from pathlib import Path

from app.analysis.investigation_scope import should_investigate_file_path
from app.analysis.import_resolver import ImportResolution
from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.agents.investigator import InvestigatorAgent
from app.orchestrator.scan_context import ScanContext, TaintFlow
from app.orchestrator.tools import AgentToolkit
from app.scanners.bandit import BanditAdapter
from app.scanners.base import ScannerHit
from app.scanners.codeql import CodeQLAdapter
from app.scanners.semgrep import SemgrepAdapter


def _ctx(repo_path) -> ScanContext:
    return ScanContext(
        scan_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        repo_path=str(repo_path),
        mode="regular",
    )


class _DummyAgent(BaseAgent):
    @property
    def name(self) -> str:
        return "dummy"

    async def execute(self, ctx: ScanContext) -> None:
        return None


def test_agent_toolkit_blocks_path_traversal(sample_repo):
    escape = sample_repo.parent / f"{sample_repo.name}-escape"
    escape.mkdir()
    (escape / "secret.py").write_text("print('secret')\n")

    toolkit = AgentToolkit(_ctx(sample_repo))
    result = asyncio.run(toolkit.read_file(f"../{escape.name}/secret.py"))

    assert not result.success
    assert "Path traversal blocked" in result.error


def test_agent_toolkit_list_directory_blocks_path_traversal(sample_repo):
    escape = sample_repo.parent / f"{sample_repo.name}-escape"
    escape.mkdir()

    toolkit = AgentToolkit(_ctx(sample_repo))
    result = asyncio.run(toolkit.list_directory(f"../{escape.name}"))

    assert not result.success
    assert "Path traversal blocked" in result.error


def test_query_taint_flows_exposes_graph_metadata(sample_repo):
    ctx = _ctx(sample_repo)
    ctx.taint_flows.append(
        TaintFlow(
            source_file="app.py",
            source_line=4,
            source_type="request_param",
            sink_file="db.py",
            sink_line=19,
            sink_type="sql_exec",
            intermediaries=["service.py::lookup_user"],
            confidence=0.91,
            sanitised=False,
            sanitiser_location="validators.py:12",
            call_chain=[
                {"caller": "routes.py::login", "callee": "service.py::lookup_user"},
                {"caller": "service.py::lookup_user", "callee": "db.py::query_user"},
            ],
            graph_verified=True,
        )
    )

    toolkit = AgentToolkit(ctx)
    result = asyncio.run(toolkit.query_taint_flows())

    assert result.success
    assert len(result.data) == 1
    flow = result.data[0]
    assert flow["graph_verified"] is True
    assert flow["confidence"] == 0.91
    assert flow["sanitiser_location"] == "validators.py:12"
    assert flow["call_chain_hops"] == 2
    assert len(flow["call_chain"]) == 2


def test_openai_tool_schemas_include_extended_navigation_tools():
    tools = AgentToolkit.get_openai_tools(
        tool_names=[
            "list_directory",
            "check_file_exists",
            "get_file_imports",
            "get_callers_of",
            "get_entry_points_reaching",
            "run_codeql_on_files",
        ]
    )

    names = [tool["function"]["name"] for tool in tools]

    assert names == [
        "list_directory",
        "check_file_exists",
        "get_file_imports",
        "get_callers_of",
        "get_entry_points_reaching",
        "run_codeql_on_files",
    ]


def test_agent_toolkit_normalises_targeted_files_to_repo(sample_repo):
    escape = sample_repo.parent / f"{sample_repo.name}-escape"
    escape.mkdir()
    (escape / "secret.py").write_text("print('secret')\n")

    toolkit = AgentToolkit(_ctx(sample_repo))
    safe_files = toolkit.normalise_repo_files(["app.py", f"../{escape.name}/secret.py", "app.py"])

    assert safe_files == ["app.py"]


def test_investigation_scope_keeps_security_relevant_non_code_files():
    assert should_investigate_file_path("config/settings.yaml") is True
    assert should_investigate_file_path("templates/login.html") is True
    assert should_investigate_file_path("infra/Dockerfile") is True
    assert should_investigate_file_path("package-lock.json") is True
    assert should_investigate_file_path("docs/README.md") is False
    assert should_investigate_file_path("static/app.min.js") is False


def test_investigation_prompt_inlines_richer_scanner_context(sample_repo):
    ctx = _ctx(sample_repo)
    investigator = InvestigatorAgent(llm=None)

    prompt = investigator._build_investigation_prompt(
        ctx,
        "templates/login.html",
        "<div>{{ user_input }}</div>",
        [
            {
                "scanner": "codeql",
                "rule_id": "js/xss-through-dom",
                "message": "Untrusted input reaches HTML rendering",
                "line": 12,
                "end_line": 18,
                "severity": "high",
                "snippet": "element.innerHTML = userInput;",
                "metadata_summary": "Flow: routes.js:4 -> templates/login.html:12 | CWEs: CWE-79",
            }
        ],
        related_files=[],
        vuln_functions=[],
        dep_context=[],
    )

    assert "Scanner signals for templates/login.html" in prompt
    assert "codeql::js/xss-through-dom at lines 12-18" in prompt
    assert "Context: Flow: routes.js:4 -> templates/login.html:12 | CWEs: CWE-79" in prompt
    assert "Snippet:" in prompt


def test_large_single_line_reads_are_bounded_for_toolkit_and_base_agent(sample_repo):
    large_file = sample_repo / "large.py"
    large_file.write_text("A" * 250_000)

    toolkit = AgentToolkit(_ctx(sample_repo))
    toolkit_result = asyncio.run(toolkit.read_file("large.py", max_lines=20))

    assert toolkit_result.success
    assert len(toolkit_result.data) < 210_500
    assert "truncated at 200,000 bytes" in toolkit_result.data

    agent = _DummyAgent(llm=None)
    agent_result = asyncio.run(agent.read_file(_ctx(sample_repo), "large.py", max_lines=20))

    assert len(agent_result) < 210_500
    assert "truncated at 200,000 bytes" in agent_result


def test_scanner_adapters_filter_out_escaped_files(sample_repo):
    escape = sample_repo.parent / f"{sample_repo.name}-escape"
    escape.mkdir()
    (escape / "secret.py").write_text("print('secret')\n")

    bandit_files = BanditAdapter._normalise_repo_files(
        sample_repo,
        ["app.py", f"../{escape.name}/secret.py", "config.py"],
    )
    semgrep_files = SemgrepAdapter._normalise_repo_files(
        sample_repo,
        ["server.js", f"../{escape.name}/secret.py", "server.js"],
    )

    assert bandit_files == ["app.py", "config.py"]
    assert semgrep_files == ["server.js"]


def test_codeql_query_matches_language_prefix():
    assert CodeQLAdapter._query_matches_language("python", "python-security-experimental.qls")
    assert CodeQLAdapter._query_matches_language("javascript", "typescript-security-experimental.qls")
    assert not CodeQLAdapter._query_matches_language("python", "javascript-security-experimental.qls")


def test_codeql_baseline_queries_follow_scan_mode():
    adapter = CodeQLAdapter()

    light = adapter._baseline_queries_for_mode("javascript", "light")
    regular = adapter._baseline_queries_for_mode("javascript", "regular")
    heavy = adapter._baseline_queries_for_mode("javascript", "heavy")

    assert light == ["javascript-security-extended.qls"]
    assert regular == [
        "javascript-security-extended.qls",
        "javascript-security-and-quality.qls",
    ]
    assert heavy == [
        "javascript-security-extended.qls",
        "javascript-security-and-quality.qls",
        "javascript-security-experimental.qls",
    ]


def test_codeql_plan_targeted_queries_dedupes_typescript_aliases():
    adapter = CodeQLAdapter()
    planned = adapter._plan_targeted_queries(
        "javascript",
        [
            "typescript-security-experimental.qls",
            "javascript-security-experimental.qls",
            "javascript-security-and-quality.qls",
        ],
    )

    assert planned == [
        "javascript-security-experimental.qls",
        "javascript-security-and-quality.qls",
    ]


def test_codeql_dedupe_hits_merges_suite_metadata():
    hits = [
        ScannerHit(
            rule_id="codeql/js-command-injection",
            severity="high",
            message="Dangerous command execution",
            file_path="src/app.js",
            start_line=12,
            metadata={
                "fingerprint": "abc123",
                "query_suites": ["javascript-security-and-quality.qls"],
                "tags": ["external/cwe/cwe-78"],
                "cwes": ["external/cwe/cwe-78"],
            },
        ),
        ScannerHit(
            rule_id="codeql/js-command-injection",
            severity="high",
            message="Dangerous command execution",
            file_path="src/app.js",
            start_line=12,
            metadata={
                "fingerprint": "abc123",
                "query_suites": ["javascript-security-experimental.qls"],
                "tags": ["security"],
                "cwes": ["external/cwe/cwe-78"],
                "has_data_flow": True,
                "data_flow_steps": [{"file": "src/app.js", "line": 12, "message": "sink"}],
            },
        ),
    ]

    deduped = CodeQLAdapter._dedupe_hits(hits)

    assert len(deduped) == 1
    assert deduped[0].metadata["matched_suites"] == [
        "javascript-security-and-quality.qls",
        "javascript-security-experimental.qls",
    ]
    assert deduped[0].metadata["has_data_flow"] is True


def test_codeql_resolve_build_strategy_prefers_gradle_wrapper(tmp_path):
    (tmp_path / "gradlew.bat").write_text("", encoding="utf-8")
    (tmp_path / "build.gradle").write_text("plugins {}", encoding="utf-8")

    strategy = CodeQLAdapter._resolve_build_strategy(tmp_path, "java")

    assert strategy["kind"] == "command"
    assert "gradlew.bat" in strategy["value"]
    assert strategy["retry_with_none"] is True


def test_codeql_resolve_build_strategy_uses_dotnet_solution(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "App.sln").write_text("", encoding="utf-8")

    strategy = CodeQLAdapter._resolve_build_strategy(tmp_path, "csharp")

    assert strategy["kind"] == "command"
    assert "dotnet build" in strategy["value"]
    assert "App.sln" in strategy["value"]


def test_codeql_resolve_build_strategy_composes_gradle_workspace_builds(tmp_path):
    (tmp_path / "services" / "api").mkdir(parents=True)
    (tmp_path / "libs" / "core").mkdir(parents=True)
    (tmp_path / "services" / "api" / "build.gradle").write_text("plugins {}", encoding="utf-8")
    (tmp_path / "libs" / "core" / "build.gradle.kts").write_text("plugins {}", encoding="utf-8")

    strategy = CodeQLAdapter._resolve_build_strategy(tmp_path, "java")

    assert strategy["kind"] == "command"
    assert 'gradle -p "libs/core" build -x test --no-daemon' in strategy["value"]
    assert 'gradle -p "services/api" build -x test --no-daemon' in strategy["value"]
    assert " && " in strategy["value"]


def test_codeql_resolve_build_strategy_prefers_root_maven_aggregator(tmp_path):
    (tmp_path / "pom.xml").write_text(
        "<project>"
        "<modelVersion>4.0.0</modelVersion>"
        "<groupId>example</groupId>"
        "<artifactId>root</artifactId>"
        "<packaging>pom</packaging>"
        "<modules><module>service</module></modules>"
        "</project>",
        encoding="utf-8",
    )
    (tmp_path / "service").mkdir()
    (tmp_path / "service" / "pom.xml").write_text(
        "<project><modelVersion>4.0.0</modelVersion></project>",
        encoding="utf-8",
    )

    strategy = CodeQLAdapter._resolve_build_strategy(tmp_path, "java")

    assert strategy["kind"] == "command"
    assert strategy["value"] == "mvn -q -DskipTests compile"


def test_codeql_resolve_build_strategy_composes_swift_packages(tmp_path):
    (tmp_path / "Apps" / "Client").mkdir(parents=True)
    (tmp_path / "Packages" / "Shared").mkdir(parents=True)
    (tmp_path / "Apps" / "Client" / "Package.swift").write_text("// swift-tools-version: 5.9", encoding="utf-8")
    (tmp_path / "Packages" / "Shared" / "Package.swift").write_text("// swift-tools-version: 5.9", encoding="utf-8")

    strategy = CodeQLAdapter._resolve_build_strategy(tmp_path, "swift")

    assert strategy["kind"] == "command"
    assert 'swift build --package-path "Apps/Client"' in strategy["value"]
    assert 'swift build --package-path "Packages/Shared"' in strategy["value"]


class _ProbeInvestigator(InvestigatorAgent):
    def __init__(self):
        super().__init__(llm=None)
        self.captured_tool_names = None

    async def ask_json(self, ctx, system, user, **kwargs):
        self.captured_tool_names = kwargs.get("tool_names")
        return {}

    async def emit(self, ctx, message, *, level="info", detail=None):
        return None


def test_investigator_primary_investigation_allows_codeql_tool(tmp_path):
    app_file = tmp_path / "app.py"
    app_file.write_text("print('hello')\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    ctx.files_total = 1

    agent = _ProbeInvestigator()

    async def _run():
        agent._get_related_file_snippets = lambda *args, **kwargs: asyncio.sleep(0, result=[])
        agent._get_scanner_hits = lambda *args, **kwargs: asyncio.sleep(0, result="")
        await agent._investigate_file(ctx, "app.py")

    asyncio.run(_run())

    assert agent.captured_tool_names is not None
    assert "run_codeql_on_files" in agent.captured_tool_names


def test_investigator_dep_context_prefers_import_graph_matches(tmp_path):
    app_file = tmp_path / "app.py"
    app_file.write_text("load(payload)\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    ctx.import_graph = {
        "app.py": [
            ImportResolution(
                import_module="yaml",
                imported_names=["load"],
                is_external=True,
                source_file="app.py",
                line=1,
            )
        ]
    }
    ctx._dep_cache = {
        "entries": [
            {
                "package": "pyyaml",
                "version": "5.4",
                "ecosystem": "pypi",
                "advisory_id": "GHSA-1234",
                "cve_id": "",
                "severity": "high",
                "summary": "Unsafe yaml loader",
                "details": "",
                "fixed_version": "6.0",
                "cwes": ["CWE-20"],
                "references": [],
                "vulnerable_functions": ["load"],
                "evidence_type": "dep_audit",
                "ai_assessment": "",
                "relevance": "used",
                "reachability_status": "reachable",
                "risk_score": 820.0,
            }
        ]
    }

    agent = InvestigatorAgent(llm=None)
    matches = agent._get_dep_context_for_file(ctx, "app.py")

    assert len(matches) == 1
    assert matches[0]["package"] == "pyyaml"
    assert matches[0]["import_match_source"] == "import_graph"
    assert matches[0]["import_module"] == "yaml"


def test_investigator_prompt_labels_weak_vulnerable_function_overlaps(tmp_path):
    app_file = tmp_path / "app.py"
    app_file.write_text("load(payload)\n", encoding="utf-8")
    ctx = _ctx(tmp_path)
    agent = InvestigatorAgent(llm=None)

    prompt = agent._build_investigation_prompt(
        ctx,
        "app.py",
        "load(payload)\n",
        [],
        vuln_functions=[
            {
                "function": "load",
                "line": 1,
                "display_id": "GHSA-weak-1",
                "severity": "high",
                "package": "pyyaml",
                "summary": "Unsafe yaml loader",
                "evidence_strength": "weak",
                "package_evidence_source": "function_name_only",
                "package_match_confidence": 0.25,
            }
        ],
        dep_context=[],
    )

    assert "Weak Advisory Function-Name Overlaps" in prompt
    assert "not confirmed as imported in this file" in prompt
