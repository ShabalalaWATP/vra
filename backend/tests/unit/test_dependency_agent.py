"""Tests for dependency-risk usage heuristics."""

from types import SimpleNamespace
import uuid

import pytest

from app.analysis.import_resolver import ImportResolution
from app.analysis.treesitter import TSCallSite, TSFileAnalysis
from app.orchestrator.agents.dependency import DependencyRiskAgent


def test_dependency_usage_tokens_include_pub_import_patterns():
    tokens = DependencyRiskAgent._dependency_usage_tokens("http", "pub")

    assert "http" in tokens
    assert "package:http/" in tokens


def test_dependency_usage_tokens_include_hex_module_patterns():
    tokens = DependencyRiskAgent._dependency_usage_tokens("phoenix_html", "hex")

    assert "phoenix_html" in tokens
    assert "phoenix.html" in tokens
    assert "phoenixhtml" in tokens


def test_dependency_usage_tokens_include_curated_pypi_import_aliases():
    tokens = DependencyRiskAgent._dependency_usage_tokens("pyjwt", "pypi")

    assert "jwt" in tokens


def test_classify_relevance_marks_direct_imports_as_used(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    dep = SimpleNamespace(
        name="requests",
        ecosystem="pypi",
        is_dev=False,
        source_file="requirements.txt",
    )

    relevance, assessment = agent._classify_relevance(
        dep,
        [{"file": "app/main.py", "kind": "import"}],
        tmp_path,
    )

    assert relevance == "used"
    assert "app/main.py" in assessment


def test_classify_relevance_marks_symbol_references_as_likely_used(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    dep = SimpleNamespace(
        name="phoenix_html",
        ecosystem="hex",
        is_dev=False,
        source_file="mix.lock",
    )

    relevance, assessment = agent._classify_relevance(
        dep,
        [{"file": "lib/app_web/components.ex", "kind": "reference"}],
        tmp_path,
    )

    assert relevance == "likely_used"
    assert "components.ex" in assessment


def test_classify_relevance_marks_test_only_usage(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    dep = SimpleNamespace(
        name="pytest",
        ecosystem="pypi",
        is_dev=True,
        source_file="requirements-dev.txt",
    )

    relevance, assessment = agent._classify_relevance(
        dep,
        [{"file": "tests/test_auth.py", "kind": "import"}],
        tmp_path,
    )

    assert relevance == "test_only"
    assert "tests/test_auth.py" in assessment


def test_classify_relevance_marks_lockfile_only_dependencies_as_transitive(tmp_path):
    repo_root = tmp_path
    (repo_root / "package-lock.json").write_text("{}", encoding="utf-8")
    (repo_root / "package.json").write_text(
        '{"dependencies": {"react": "^18.0.0"}}',
        encoding="utf-8",
    )

    agent = DependencyRiskAgent(llm=None)
    dep = SimpleNamespace(
        name="left-pad",
        ecosystem="npm",
        is_dev=False,
        source_file="package-lock.json",
    )

    relevance, assessment = agent._classify_relevance(dep, [], repo_root)

    assert relevance == "transitive_only"
    assert "lockfile" in assessment.lower()


def test_infer_reachability_marks_vulnerable_function_hits_as_reachable(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    dep = SimpleNamespace(
        name="lodash",
        ecosystem="npm",
        is_dev=False,
        source_file="package-lock.json",
    )

    reachability, confidence = agent._infer_reachability(
        dep,
        "used",
        [{"file": "src/index.js", "kind": "import"}],
        [{"file": "src/index.js", "kind": "vulnerable_function", "symbol": "merge"}],
    )

    assert reachability == "reachable"
    assert confidence >= 0.8


@pytest.mark.asyncio
async def test_find_import_usage_prefers_import_graph_for_external_imports(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    ctx = SimpleNamespace(
        scan_id=uuid.uuid4(),
        repo_path=str(tmp_path),
        import_graph={
            "src/main.py": [
                ImportResolution(
                    import_module="jinja2",
                    is_external=True,
                    source_file="src/main.py",
                )
            ]
        },
        file_analyses={},
    )
    dep = SimpleNamespace(name="jinja2", ecosystem="pypi")

    usage = await agent._find_import_usage(ctx, [(None, dep)])

    assert usage["jinja2"][0]["file"] == "src/main.py"
    assert usage["jinja2"][0]["kind"] == "import"
    assert usage["jinja2"][0]["source"] == "import_graph"


@pytest.mark.asyncio
async def test_find_import_usage_matches_curated_python_import_alias(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    ctx = SimpleNamespace(
        scan_id=uuid.uuid4(),
        repo_path=str(tmp_path),
        import_graph={
            "src/auth.py": [
                ImportResolution(
                    import_module="jwt",
                    is_external=True,
                    source_file="src/auth.py",
                )
            ]
        },
        file_analyses={},
    )
    dep = SimpleNamespace(name="pyjwt", ecosystem="pypi")

    usage = await agent._find_import_usage(ctx, [(None, dep)])

    assert usage[dep.name][0]["file"] == "src/auth.py"
    assert usage[dep.name][0]["kind"] == "import"
    assert usage[dep.name][0]["source"] == "import_graph"


@pytest.mark.asyncio
async def test_find_import_usage_marks_maven_namespace_matches_as_reference(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    ctx = SimpleNamespace(
        scan_id=uuid.uuid4(),
        repo_path=str(tmp_path),
        import_graph={
            "src/App.java": [
                ImportResolution(
                    import_module="org.apache.logging.log4j.Logger",
                    is_external=True,
                    source_file="src/App.java",
                )
            ]
        },
        file_analyses={},
    )
    dep = SimpleNamespace(name="org.apache.logging.log4j:log4j-core", ecosystem="maven")

    usage = await agent._find_import_usage(ctx, [(None, dep)])

    assert usage[dep.name][0]["file"] == "src/App.java"
    assert usage[dep.name][0]["kind"] == "reference"
    assert usage[dep.name][0]["source"] == "import_graph"


@pytest.mark.asyncio
async def test_find_import_usage_matches_curated_maven_namespace_alias(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    ctx = SimpleNamespace(
        scan_id=uuid.uuid4(),
        repo_path=str(tmp_path),
        import_graph={
            "src/JsonUtil.java": [
                ImportResolution(
                    import_module="com.fasterxml.jackson.databind.ObjectMapper",
                    is_external=True,
                    source_file="src/JsonUtil.java",
                )
            ]
        },
        file_analyses={},
    )
    dep = SimpleNamespace(name="com.fasterxml.jackson.core:jackson-databind", ecosystem="maven")

    usage = await agent._find_import_usage(ctx, [(None, dep)])

    assert usage[dep.name][0]["file"] == "src/JsonUtil.java"
    assert usage[dep.name][0]["kind"] == "reference"
    assert usage[dep.name][0]["source"] == "import_graph"


def test_find_vulnerable_function_usage_uses_imported_files_and_call_sites(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    app_file = tmp_path / "src" / "app.js"
    app_file.parent.mkdir(parents=True)
    app_file.write_text("_.merge(user, payload);\n", encoding="utf-8")

    ctx = SimpleNamespace(
        repo_path=str(tmp_path),
        file_analyses={
            "src/app.js": TSFileAnalysis(
                language="javascript",
                call_sites=[
                    TSCallSite(
                        callee_name="merge",
                        callee_object="_",
                        line=1,
                        full_expression="_.merge",
                        is_method_call=True,
                    )
                ],
            )
        },
    )
    dep = SimpleNamespace(source_file="package-lock.json")
    finding = SimpleNamespace(vulnerable_functions=["_.merge"])

    evidence = agent._find_vulnerable_function_usage(
        ctx,
        dep,
        finding,
        [
            {"file": "src/app.js", "kind": "import", "source": "import_graph"},
            {"file": "package-lock.json", "kind": "reference", "source": "text_fallback"},
        ],
    )

    assert evidence == [
        {
            "file": "src/app.js",
            "kind": "vulnerable_function",
            "symbol": "_.merge",
            "line": 1,
        }
    ]


def test_find_vulnerable_function_usage_skips_manifest_only_hits(tmp_path):
    agent = DependencyRiskAgent(llm=None)
    ctx = SimpleNamespace(repo_path=str(tmp_path), file_analyses={})
    dep = SimpleNamespace(source_file="package-lock.json")
    finding = SimpleNamespace(vulnerable_functions=["_.merge"])

    evidence = agent._find_vulnerable_function_usage(
        ctx,
        dep,
        finding,
        [{"file": "package-lock.json", "kind": "reference", "source": "text_fallback"}],
    )

    assert evidence == []
