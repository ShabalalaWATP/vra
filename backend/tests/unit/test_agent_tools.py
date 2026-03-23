"""Tests for agent tool safety and taint-flow metadata exposure."""

import asyncio
import uuid

from app.orchestrator.agents.base import BaseAgent
from app.orchestrator.scan_context import ScanContext, TaintFlow
from app.orchestrator.tools import AgentToolkit
from app.scanners.bandit import BanditAdapter
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
        ]
    )

    names = [tool["function"]["name"] for tool in tools]

    assert names == [
        "list_directory",
        "check_file_exists",
        "get_file_imports",
        "get_callers_of",
        "get_entry_points_reaching",
    ]


def test_agent_toolkit_normalises_targeted_files_to_repo(sample_repo):
    escape = sample_repo.parent / f"{sample_repo.name}-escape"
    escape.mkdir()
    (escape / "secret.py").write_text("print('secret')\n")

    toolkit = AgentToolkit(_ctx(sample_repo))
    safe_files = toolkit.normalise_repo_files(["app.py", f"../{escape.name}/secret.py", "app.py"])

    assert safe_files == ["app.py"]


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
