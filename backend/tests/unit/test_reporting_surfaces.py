"""Tests for reporting payloads and advisory reporting surfaces."""

import asyncio
import builtins
import json
import uuid
import zipfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from app.analysis import diagram as diagram_renderer
from app.api.reports import _report_out
from app.models.dependency import Dependency, DependencyFinding
from app.models.finding import Evidence, Finding
from app.models.report import Report
from app.models.secret_candidate import SecretCandidate
from app.orchestrator.agents.architecture import ArchitectureAgent
from app.orchestrator.agents.reporter import ReporterAgent
from app.orchestrator.agents.verifier import VerifierAgent
from app.orchestrator.scan_context import CandidateFinding, ScanContext, TaintFlow
from app.services import export_service, report_diagrams
from app.services.export_service import (
    RenderedReportDiagram,
    generate_export,
    _generate_docx,
    _generate_pdf,
    _format_related_advisories,
    _render_report_html,
)


def _ctx(tmp_path) -> ScanContext:
    return ScanContext(
        scan_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        repo_path=str(tmp_path),
        mode="regular",
    )


def _load_golden_report_fixture():
    fixture_path = Path(__file__).resolve().parent.parent / "fixtures" / "report_golden_case.json"
    payload = json.loads(fixture_path.read_text(encoding="utf-8"))

    scan_id = uuid.uuid4()
    report_payload = payload["report"]
    report = Report(
        id=uuid.uuid4(),
        scan_id=scan_id,
        app_summary=report_payload["app_summary"],
        narrative=report_payload["narrative"],
        risk_grade=report_payload["risk_grade"],
        risk_score=report_payload["risk_score"],
        architecture=json.dumps(report_payload["architecture"]),
        sbom=report_payload["sbom"],
        scan_coverage=report_payload["scan_coverage"],
        tech_stack=report_payload["tech_stack"],
        scanner_hits=report_payload["scanner_hits"],
        attack_surface=report_payload["attack_surface"],
    )

    findings: list[Finding] = []
    for finding_payload in payload["findings"]:
        finding = Finding(
            id=uuid.uuid4(),
            scan_id=scan_id,
            title=finding_payload["title"],
            severity=finding_payload["severity"],
            confidence=finding_payload["confidence"],
            category=finding_payload["category"],
            description=finding_payload["description"],
            explanation=finding_payload.get("explanation"),
            impact=finding_payload.get("impact"),
            remediation=finding_payload.get("remediation"),
            exploit_difficulty=finding_payload.get("exploit_difficulty"),
            exploit_prerequisites=finding_payload.get("exploit_prerequisites"),
            exploit_template=finding_payload.get("exploit_template"),
            attack_scenario=finding_payload.get("attack_scenario"),
            exploit_evidence=finding_payload.get("exploit_evidence"),
            related_cves=finding_payload.get("related_cves"),
        )
        if finding_payload.get("evidence"):
            finding.evidence = [
                Evidence(type="supporting", description=description)
                for description in finding_payload["evidence"]
            ]
        findings.append(finding)

    dep_findings: list[tuple[DependencyFinding, Dependency]] = []
    for dep_payload in payload["dependency_findings"]:
        dependency = Dependency(
            id=uuid.uuid4(),
            scan_id=scan_id,
            ecosystem=dep_payload["dependency"]["ecosystem"],
            name=dep_payload["dependency"]["name"],
            version=dep_payload["dependency"]["version"],
            source_file=dep_payload["dependency"]["source_file"],
            is_dev=dep_payload["dependency"]["is_dev"],
        )
        dependency_finding = DependencyFinding(
            dependency_id=dependency.id,
            scan_id=scan_id,
            advisory_id=dep_payload["finding"].get("advisory_id"),
            cve_id=dep_payload["finding"].get("cve_id"),
            severity=dep_payload["finding"].get("severity"),
            summary=dep_payload["finding"].get("summary"),
            fixed_version=dep_payload["finding"].get("fixed_version"),
            vulnerable_functions=dep_payload["finding"].get("vulnerable_functions"),
            evidence_type=dep_payload["finding"].get("evidence_type", "exact_package_match"),
            relevance=dep_payload["finding"].get("relevance", "unknown"),
            usage_evidence=dep_payload["finding"].get("usage_evidence"),
            reachability_status=dep_payload["finding"].get("reachability_status", "unknown"),
            reachability_confidence=dep_payload["finding"].get("reachability_confidence"),
            risk_score=dep_payload["finding"].get("risk_score"),
            ai_assessment=dep_payload["finding"].get("ai_assessment"),
        )
        dep_findings.append((dependency_finding, dependency))

    diagrams = [
        RenderedReportDiagram(
            title=diagram["title"],
            description=diagram.get("description", ""),
            image_bytes=diagram["svg"].encode("utf-8"),
            media_type=diagram.get("media_type", "image/svg+xml"),
        )
        for diagram in payload["diagrams"]
    ]

    return {
        "report": report,
        "findings": findings,
        "secrets": [],
        "dep_findings": dep_findings,
        "diagrams": diagrams,
    }


def test_reporter_build_architecture_payload_adds_result_aware_diagrams(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.architecture_notes = (
        '{"components":[{"name":"API","files":["api"],"criticality":"critical","in_attack_surface":true}],'
        '"auth_mechanisms":[{"type":"jwt","implementation":"api/auth.py"}],'
        '"external_integrations":["postgres"],'
        '"data_flows":[{"from":"Browser","to":"API","data":"credentials","sensitive":true}],'
        '"diagrams":['
        '{"title":"System Overview","description":"legacy","mermaid":"flowchart TD\\n    A[fa:server API]"},'
        '{"title":"Security Architecture","mermaid":"flowchart TD\\n    B-->C"},'
        '{"title":"Data Flow","mermaid":"flowchart LR\\n    C-->D"},'
        '{"title":"Attack Surface","mermaid":"flowchart TD\\n    D-->E"}]}'
    )
    ctx.trust_boundaries = ["Public HTTP boundary"]
    ctx.entry_points = [{"file": "api/routes.py", "function": "login", "path": "/login"}]
    ctx.attack_surface = ["api/routes.py::login POST /login"]
    ctx.candidate_findings = [
        CandidateFinding(
            title="Command injection in admin task runner",
            category="command_exec",
            severity="critical",
            file_path="api/tasks.py",
            confidence=0.92,
            status="confirmed",
            provenance="hybrid",
            verification_level="strongly_verified",
            merge_metadata={"merged_count": 2},
            related_cves=[{"display_id": "CVE-2026-1000", "summary": "unsafe call", "severity": "high", "package": "pyyaml"}],
        ),
        CandidateFinding(
            title="Weak access control on export endpoint",
            category="auth",
            severity="high",
            file_path="api/routes.py",
            confidence=0.81,
            status="confirmed",
            provenance="scanner",
            verification_level="statically_verified",
        ),
        CandidateFinding(
            title="Unsigned webhook replay path",
            category="auth",
            severity="medium",
            file_path="api/webhooks.py",
            confidence=0.67,
            status="confirmed",
            provenance="llm",
            verification_level="hypothesis",
        ),
    ]

    dep = Dependency(
        scan_id=ctx.scan_id,
        ecosystem="pypi",
        name="pyyaml",
        version="5.4",
        source_file="requirements.txt",
        is_dev=False,
    )
    dep_finding = DependencyFinding(
        dependency_id=uuid.uuid4(),
        scan_id=ctx.scan_id,
        advisory_id="GHSA-pypi-2222",
        cve_id="CVE-2020-1747",
        severity="high",
        summary="Unsafe yaml loader",
        fixed_version="6.0",
        vulnerable_functions=["load"],
        evidence_type="confirmed_vulnerable_dependency_function_match",
        relevance="used",
        usage_evidence=[{"file": "api/tasks.py", "kind": "vulnerable_function", "symbol": "load", "line": 19}],
        reachability_status="reachable",
        reachability_confidence=0.97,
        risk_score=845.0,
        ai_assessment="Reached from API code.",
    )

    payload = ReporterAgent(llm=None)._build_architecture_payload(ctx, [(dep_finding, dep)])

    assert payload["result_summary"]["finding_count"] == 3
    assert payload["result_summary"]["critical_count"] == 1
    assert payload["result_summary"]["exploit_chain_count"] == 0
    assert payload["result_summary"]["advisory_correlated_count"] == 1
    assert payload["result_summary"]["scanner_only_count"] == 1
    assert payload["result_summary"]["llm_only_count"] == 1
    assert payload["result_summary"]["hybrid_count"] == 1
    assert payload["result_summary"]["statically_verified_count"] == 1
    assert payload["result_summary"]["strongly_verified_count"] == 1
    assert payload["result_summary"]["hypothesis_count"] == 1
    assert payload["result_summary"]["merged_duplicate_count"] == 1
    assert payload["result_summary"]["reachable_dependency_count"] == 1
    assert payload["component_hotspots"][0]["name"] == "API"
    assert payload["component_hotspots"][0]["max_severity"] == "critical"
    assert payload["attack_surface"] == ["api/routes.py::login POST /login"]
    assert payload["data_flows"][0]["data"] == "credentials"
    assert any("AI-led investigation" in observation for observation in payload["security_observations"])
    assert any("strong static verification" in observation for observation in payload["security_observations"])
    assert [diagram["title"] for diagram in payload["diagrams"][:4]] == [
        "System Overview",
        "Security Architecture",
        "Data Flow",
        "Attack Surface",
    ]
    assert [diagram["kind"] for diagram in payload["diagrams"][:4]] == [
        "overview",
        "security",
        "data_flow",
        "attack_surface",
    ]
    assert len(payload["diagrams"]) == 7
    assert any(diagram["title"] == "Dependency Exposure And Reachability" for diagram in payload["diagrams"])
    assert any(diagram["title"] == "Verified Security Overview" for diagram in payload["diagrams"])


def test_architecture_agent_normalises_canonical_diagrams_and_kinds():
    diagrams = ArchitectureAgent._normalise_architecture_diagrams(
        [
            {"title": "Attack Surface", "mermaid": "flowchart TD\nD-->E"},
            {"title": "Overview", "mermaid": "flowchart TD\nA-->B"},
            {"title": "Data Flow", "mermaid": "flowchart LR\nB-->C"},
            {"title": "Security Architecture", "mermaid": "flowchart TD\nC-->D"},
        ]
    )

    assert [diagram["title"] for diagram in diagrams] == [
        "System Overview",
        "Security Architecture",
        "Data Flow",
        "Attack Surface",
    ]
    assert [diagram["kind"] for diagram in diagrams] == [
        "overview",
        "security",
        "data_flow",
        "attack_surface",
    ]


def test_reporter_merge_diagrams_preserves_original_canonical_diagrams_first():
    merged = ReporterAgent._merge_diagrams(
        [
            {"title": "Attack Surface", "kind": "attack_surface", "mermaid": "flowchart TD\nD-->E"},
            {"title": "System Overview", "kind": "overview", "mermaid": "flowchart TD\nA-->B"},
            {"title": "Data Flow", "kind": "data_flow", "mermaid": "flowchart LR\nB-->C"},
            {"title": "Security Architecture", "kind": "security", "mermaid": "flowchart TD\nC-->D"},
        ],
        [
            {"title": "Verified Security Overview", "kind": "result_overview", "mermaid": "flowchart TD\nE-->F"},
            {"title": "Trust Boundaries And Hotspots", "kind": "trust_boundaries", "mermaid": "flowchart TD\nF-->G"},
            {"title": "Dependency Exposure And Reachability", "kind": "dependency_risk", "mermaid": "flowchart LR\nG-->H"},
        ],
    )

    assert [diagram["kind"] for diagram in merged] == [
        "overview",
        "security",
        "data_flow",
        "attack_surface",
        "result_overview",
        "trust_boundaries",
        "dependency_risk",
    ]
    assert [diagram["title"] for diagram in merged[:4]] == [
        "System Overview",
        "Security Architecture",
        "Data Flow",
        "Attack Surface",
    ]


def test_reporter_prompt_includes_precomputed_enrichments(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.app_summary = "A FastAPI service that manages customer orders."
    ctx.languages = ["python"]
    ctx.frameworks = ["fastapi"]
    ctx.compaction_summaries = ["Compaction summary: login and export flows were the dominant hot paths."]

    prompt = ReporterAgent(llm=None)._build_report_prompt(
        ctx,
        dependency_summary="## Dependency Exposure\n- 2 reachable dependency risks",
        architecture_payload={
            "result_summary": {
                "finding_count": 3,
                "critical_count": 1,
                "high_count": 1,
                "exploit_chain_count": 1,
                "scanner_only_count": 1,
                "llm_only_count": 1,
                "hybrid_count": 1,
                "hypothesis_count": 1,
                "statically_verified_count": 1,
                "strongly_verified_count": 1,
                "merged_finding_count": 1,
                "merged_duplicate_count": 2,
                "reachable_dependency_count": 2,
            },
            "component_hotspots": [
                {"name": "API", "finding_count": 2, "max_severity": "critical"},
            ],
            "diagrams": [
                {"title": "Verified Security Overview", "mermaid": "flowchart TD\nA-->B"},
                {"title": "Trust Boundaries And Hotspots", "mermaid": "flowchart TD\nB-->C"},
            ],
            "trust_boundaries": ["Public API boundary"],
            "entry_points": [
                {"file": "api/routes.py", "function": "login", "method": "POST", "path": "/login", "type": "http_endpoint"},
            ],
            "data_flows": [
                {"from": "Browser", "to": "Order API", "data": "credentials", "sensitive": True},
            ],
            "attack_surface": ["api/routes.py::login POST /login"],
            "auth_mechanisms": [{"type": "jwt", "implementation": "api/auth.py"}],
            "external_integrations": ["postgres"],
        },
        scan_coverage={
            "total_files": 100,
            "files_indexed": 95,
            "files_inspected_by_ai": 18,
            "ai_calls_made": 12,
            "scanners_used": ["semgrep", "bandit"],
        },
        risk_score=61.0,
        risk_grade="F",
        component_scores={
            "API": {"grade": "F", "score": 20, "criticality": "critical", "finding_count": 2},
        },
        sbom={"total_components": 12, "vulnerable_components": 3, "ecosystems": {"pypi": 12}},
    )

    assert "Final Reporting Enrichments" in prompt
    assert "Risk score ready for final report: 61.0 (F)" in prompt
    assert "Finding sources: scanner-led=1, llm-only=1, hybrid=1" in prompt
    assert "Verification levels: hypothesis=1, statically_verified=1, strongly_verified=1, runtime_validated=0" in prompt
    assert "Duplicate merge summary: 1 canonical findings absorbed 2 duplicate candidates" in prompt
    assert "Component hotspots: API (2 findings, critical)" in prompt
    assert "Diagrams prepared for export/UI: Verified Security Overview, Trust Boundaries And Hotspots" in prompt
    assert "Entry point: POST /login in api/routes.py::login [http_endpoint]" in prompt
    assert "Data flow: Browser -> Order API carrying credentials [sensitive]" in prompt
    assert "Concrete attack surface point: api/routes.py::login POST /login" in prompt
    assert "Compaction summary: login and export flows were the dominant hot paths." in prompt


def test_reporter_prompt_includes_structured_exploit_evidence_and_advisories(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.app_summary = "An API that exports customer data."
    ctx.languages = ["python"]
    ctx.frameworks = ["fastapi"]
    ctx.components = [{"name": "Export API", "files": ["api"], "criticality": "critical"}]
    ctx.candidate_findings = [
        CandidateFinding(
            finding_id="33333333-3333-3333-3333-333333333333",
            title="Insecure export trigger",
            category="auth",
            severity="medium",
            file_path="api/export.py",
            confidence=0.84,
            status="confirmed",
            provenance="hybrid",
            verification_level="strongly_verified",
            verification_notes="Confirmed by call-graph reachability and exploit-path reasoning.",
            source_scanners=["semgrep", "eslint"],
            source_rules=["semgrep.auth.export", "eslint.security.detect-object-injection"],
            merge_metadata={"merged_count": 2},
            hypothesis="An attacker can trigger a privileged export job.",
            supporting_evidence=["Role enforcement is missing on the export route."],
            related_cves=[
                {
                    "display_id": "GHSA-export-1234",
                    "package": "fastapi",
                    "severity": "medium",
                    "summary": "Comparable missing-auth export issue",
                    "evidence_type": "related_by_cwe",
                }
            ],
            exploit_evidence={
                "difficulty": "easy",
                "target_route": "POST /api/export",
                "prerequisites": ["authenticated low-privilege account"],
                "validation_steps": ["observe export job creation"],
                "cleanup_notes": ["delete the generated export artifact"],
                "exploit_template": "curl -X POST https://target/api/export",
                "attack_scenario": "Abuse the export route to generate a privileged dataset.",
                "components": ["Export API"],
                "related_entry_points": ["POST /api/export in api/routes.py::export_data"],
                "related_taint_flows": ["request_param api/routes.py:12 -> queue_enqueue api/export.py:48"],
            },
        )
    ]

    prompt = ReporterAgent(llm=None)._build_report_prompt(
        ctx,
        dependency_summary="",
        architecture_payload={},
        scan_coverage={},
        risk_score=None,
        risk_grade=None,
        component_scores={},
        sbom={},
    )

    assert "Related advisories: GHSA-export-1234 | MEDIUM | fastapi | related by cwe" in prompt
    assert "Finding source: hybrid" in prompt
    assert "Verification level: strongly verified" in prompt
    assert "Verification notes: Confirmed by call-graph reachability and exploit-path reasoning." in prompt
    assert "Source scanners: semgrep, eslint" in prompt
    assert "Source rules: semgrep.auth.export, eslint.security.detect-object-injection" in prompt
    assert "Merged duplicate candidates: 2" in prompt
    assert "Target route or invocation: POST /api/export" in prompt
    assert "Validation steps: observe export job creation" in prompt
    assert "Cleanup notes: delete the generated export artifact" in prompt
    assert "Related taint flows: request_param api/routes.py:12 -> queue_enqueue api/export.py:48" in prompt
    assert "Proof of Concept:" in prompt


def test_architecture_prompt_includes_structured_repo_signals(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.languages = ["python"]
    ctx.frameworks = ["fastapi"]
    ctx.files_total = 4
    ctx.file_analyses = {
        "api/routes.py": SimpleNamespace(
            routes=[
                {"method": "POST", "path": "/login", "line": 12},
                {"method": "POST", "path": "/export", "line": 44},
            ],
            has_main=False,
            imports=[SimpleNamespace(module="fastapi"), SimpleNamespace(module="app.auth.jwt")],
        ),
        "app/main.py": SimpleNamespace(
            routes=[],
            has_main=True,
            imports=[SimpleNamespace(module="uvicorn")],
        ),
        "app/auth.py": SimpleNamespace(
            routes=[],
            has_main=False,
            imports=[SimpleNamespace(module="jwt"), SimpleNamespace(module="settings")],
        ),
    }
    ctx.import_graph = {
        "api/routes.py": [
            SimpleNamespace(import_module="fastapi", is_external=True),
            SimpleNamespace(import_module="requests", is_external=True),
        ],
        "app/main.py": [SimpleNamespace(import_module="uvicorn", is_external=True)],
    }

    class _FakeGraph:
        def get_high_indegree_files(self, *, limit=10, uninspected=None):
            return [("api/routes.py", 7), ("app/auth.py", 3)][:limit]

    ctx.call_graph = _FakeGraph()

    prompt = ArchitectureAgent(llm=None)._build_prompt(
        ctx,
        {"api/routes.py": "def login(): pass", "app/main.py": "if __name__ == '__main__': pass"},
    )

    assert "## Route Inventory / Entry Point Signals" in prompt
    assert "- Route: POST /login (api/routes.py:12)" in prompt
    assert "- Signal: Main entrypoint in app/main.py" in prompt
    assert "## Call Graph Hotspots" in prompt
    assert "- api/routes.py (7 incoming calls)" in prompt
    assert "## External Integration Touchpoints" in prompt
    assert "- fastapi used by api/routes.py" in prompt
    assert "## Auth / Middleware / Config Touchpoints" in prompt
    assert "- app/auth.py [auth, config]" in prompt


def test_verifier_finalise_verified_findings_merges_duplicate_candidates(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.candidate_findings = [
        CandidateFinding(
            title="SQL injection in login query",
            category="injection",
            severity="critical",
            file_path="api/auth.py",
            confidence=0.82,
            status="confirmed",
            line_range="44-46",
            cwe_ids=["CWE-89"],
            sinks=["execute_sql"],
            source_scanners=["semgrep"],
            source_rules=["python.sql.injection"],
            provenance="scanner",
            verification_level="statically_verified",
            verification_notes="Scanner trace reaches SQL sink.",
        ),
        CandidateFinding(
            title="SQL injection in login",
            category="injection",
            severity="high",
            file_path="api/auth.py",
            confidence=0.91,
            status="confirmed",
            line_range="45-45",
            cwe_ids=["CWE-89"],
            sinks=["execute_sql"],
            source_scanners=["eslint"],
            source_rules=["security/detect-sql-injection"],
            provenance="llm",
            verification_level="strongly_verified",
            verification_notes="LLM reasoning found unsanitised input on the same sink.",
        ),
    ]

    VerifierAgent(llm=None)._finalise_verified_findings(ctx)

    assert len(ctx.candidate_findings) == 1
    finding = ctx.candidate_findings[0]
    assert finding.provenance == "hybrid"
    assert finding.verification_level == "strongly_verified"
    assert finding.source_scanners == ["semgrep", "eslint"]
    assert finding.source_rules == ["python.sql.injection", "security/detect-sql-injection"]
    assert finding.canonical_key
    assert finding.merge_metadata["merged_count"] == 2


def test_reporter_attach_finding_ids_uses_exact_keys(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.candidate_findings = [
        CandidateFinding(
            title="SQL injection in login",
            category="injection",
            severity="critical",
            file_path="api/auth.py",
            hypothesis="User-controlled input reaches a SQL sink in login.",
        ),
        CandidateFinding(
            title="Weak access control on export endpoint",
            category="auth",
            severity="high",
            file_path="api/routes.py",
            hypothesis="Export endpoint is reachable without the expected role check.",
        ),
    ]

    ReporterAgent._attach_finding_ids(
        ctx,
        [
            {
                "finding_id": "11111111-1111-1111-1111-111111111111",
                "title": "SQL injection in login",
                "severity": "critical",
                "category": "injection",
                "description": "User-controlled input reaches a SQL sink in login.",
                "file_paths": ["api/auth.py"],
            },
            {
                "finding_id": "22222222-2222-2222-2222-222222222222",
                "title": "Weak access control on export endpoint",
                "severity": "high",
                "category": "auth",
                "description": "Export endpoint is reachable without the expected role check.",
                "file_paths": ["api/routes.py"],
            },
        ],
    )

    assert ctx.candidate_findings[0].finding_id == "11111111-1111-1111-1111-111111111111"
    assert ctx.candidate_findings[1].finding_id == "22222222-2222-2222-2222-222222222222"


def test_reporter_updates_narratives_by_finding_id_not_title(tmp_path, monkeypatch):
    class _FakeResult:
        def __init__(self, findings):
            self._findings = findings

        def scalars(self):
            return self

        def all(self):
            return self._findings

    class _FakeSession:
        def __init__(self, findings):
            self._findings = findings

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def execute(self, _stmt):
            return _FakeResult(self._findings)

        async def commit(self):
            return None

    finding_id = uuid.uuid4()
    persisted = type(
        "PersistedFinding",
        (),
        {
            "id": finding_id,
            "title": "Original persisted title",
            "explanation": None,
            "impact": None,
            "remediation": None,
        },
    )()
    monkeypatch.setattr(
        "app.orchestrator.agents.reporter.async_session",
        lambda: _FakeSession([persisted]),
    )

    ctx = _ctx(tmp_path)
    agent = ReporterAgent(llm=None)

    async def _noop_emit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(agent, "emit", _noop_emit)

    asyncio.run(
        agent._update_finding_narratives(
            ctx,
            [
                {
                    "finding_id": str(finding_id),
                    "title": "Different title from prompt",
                    "explanation": "Detailed explanation",
                    "impact": "High impact",
                    "remediation": "Apply parameterisation",
                }
            ],
        )
    )

    assert persisted.explanation == "Detailed explanation"
    assert persisted.impact == "High impact"
    assert persisted.remediation == "Apply parameterisation"


def test_verifier_merge_related_advisories_prefers_package_confirmed_evidence():
    merged = VerifierAgent._merge_related_advisories(
        [
            {
                "display_id": "CVE-2026-1000",
                "cve_id": "CVE-2026-1000",
                "package": "pyyaml",
                "severity": "high",
                "summary": "Unsafe yaml loader",
                "evidence_type": "related_by_cwe",
                "evidence_strength": "contextual",
                "cwe_ids": ["CWE-20"],
            }
        ],
        [
            {
                "display_id": "CVE-2026-1000",
                "cve_id": "CVE-2026-1000",
                "package": "pyyaml",
                "severity": "high",
                "summary": "Unsafe yaml loader",
                "match_type": "confirmed_vulnerable_dependency_function_match",
                "evidence_strength": "strong",
                "package_evidence_source": "import_graph",
                "package_match_confidence": 1.0,
                "function": "load",
                "line": 42,
                "cwe_ids": ["CWE-20"],
            }
        ],
    )

    assert len(merged) == 1
    assert merged[0]["evidence_strength"] == "strong"
    assert merged[0]["evidence_type"] == "confirmed_vulnerable_dependency_function_match"
    assert merged[0]["evidence_types"] == ["confirmed_vulnerable_dependency_function_match", "related_by_cwe"]
    assert merged[0]["evidence_sources"] == ["cwe_correlation", "import_graph"]
    assert merged[0]["function"] == "load"
    assert merged[0]["line"] == 42


def test_verifier_exploit_prompt_requires_route_validation_and_code(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.entry_points = [{"file": "api/routes.py", "function": "login", "path": "/login", "type": "http"}]
    ctx.components = [{"name": "API", "files": ["api"], "criticality": "critical"}]
    ctx.taint_flows = [
        TaintFlow(
            source_file="api/routes.py",
            source_line=12,
            source_type="request_param",
            sink_file="api/auth.py",
            sink_line=44,
            sink_type="sql_exec",
            graph_verified=True,
        )
    ]
    finding = CandidateFinding(
        title="SQL injection in login",
        category="injection",
        severity="critical",
        file_path="api/auth.py",
        confidence=0.95,
        hypothesis="User-controlled input reaches a SQL execution sink in login.",
        code_snippet="cursor.execute(query)",
        input_sources=["request.form.username"],
        sinks=["cursor.execute"],
    )

    prompt = asyncio.run(
        VerifierAgent(llm=None)._build_exploit_evidence_prompt(
            ctx,
            finding,
            "def login():\n    cursor.execute(query)",
        )
    )

    assert "Generate actual code or commands" in prompt
    assert "Likely Entry Points / Routes" in prompt
    assert "/login" in prompt
    assert "expected safe validation signals" in prompt
    assert "Related Taint Flows" in prompt


def test_verifier_builds_structured_exploit_evidence_payload(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.entry_points = [{"file": "api/routes.py", "function": "login", "method": "POST", "path": "/login", "type": "http"}]
    ctx.components = [{"name": "API", "files": ["api"], "criticality": "critical"}]
    ctx.taint_flows = [
        TaintFlow(
            source_file="api/routes.py",
            source_line=12,
            source_type="request_param",
            sink_file="api/auth.py",
            sink_line=44,
            sink_type="sql_exec",
            graph_verified=True,
        )
    ]
    finding = CandidateFinding(
        title="SQL injection in login",
        category="injection",
        severity="critical",
        file_path="api/auth.py",
        confidence=0.95,
        hypothesis="User-controlled input reaches a SQL execution sink in login.",
        code_snippet="cursor.execute(query)",
    )

    payload = VerifierAgent(llm=None)._build_structured_exploit_evidence(
        ctx,
        finding,
        {
            "exploit_difficulty": "easy",
            "target_route": "POST /login",
            "prerequisites": ["valid account"],
            "validation_steps": ["observe a delayed response"],
            "cleanup_notes": ["reset the test account password"],
            "exploit_template": "sqlmap -u https://target/login",
            "attack_scenario": "Inject into the username parameter.",
        },
    )

    assert payload["difficulty"] == "easy"
    assert payload["target_route"] == "POST /login"
    assert payload["prerequisites"] == ["valid account"]
    assert payload["validation_steps"] == ["observe a delayed response"]
    assert payload["cleanup_notes"] == ["reset the test account password"]
    assert payload["components"] == ["API"]
    assert payload["related_entry_points"] == ["POST /login in api/routes.py::login [http]"]
    assert "request_param api/routes.py:12 -> sql_exec api/auth.py:44 [CALL GRAPH VERIFIED]" in payload["related_taint_flows"][0]


def test_export_related_advisory_formatting_includes_evidence_details():
    formatted = _format_related_advisories(
        [
            {
                "display_id": "GHSA-pypi-2222",
                "package": "pyyaml",
                "ecosystem": "pypi",
                "severity": "high",
                "summary": "Unsafe yaml loader when attacker input reaches load",
                "evidence_strength": "strong",
                "evidence_type": "confirmed_vulnerable_dependency_function_match",
                "import_module": "yaml",
                "function": "load",
                "line": 19,
                "fixed_version": "6.0",
            }
        ]
    )

    assert len(formatted) == 1
    assert "GHSA-pypi-2222" in formatted[0]
    assert "HIGH" in formatted[0]
    assert "Strong" in formatted[0]
    assert "import yaml" in formatted[0]
    assert "call load line 19" in formatted[0]
    assert "fix 6.0" in formatted[0]


def test_report_api_helper_preserves_narrative_and_diagram_metadata():
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        app_summary="A web API for customer logins.",
        narrative="Security review narrative.",
        architecture=(
            '{"diagrams":['
            '{"title":"Overview","mermaid":"flowchart TD\\nA-->B"},'
            '{"title":"Data Flow","mermaid":"flowchart TD\\nB-->C"}]}'
        ),
        diagram_spec="flowchart TD\nA-->B",
        diagram_image=b'<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"></svg>',
        methodology="Methodology",
        limitations="Limitations",
    )
    report.created_at = datetime(2026, 4, 12, 12, 0, 0)

    out = _report_out(report)

    assert out.narrative == "Security review narrative."
    assert out.diagram_count == 2
    assert out.diagram_media_type == "image/svg+xml"


def test_render_report_diagrams_uses_cached_primary_and_renders_remaining(monkeypatch):
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        architecture=(
            '{"diagrams":['
            '{"title":"Overview","kind":"overview","mermaid":"flowchart TD\\nA-->B"},'
            '{"title":"Trust","kind":"trust_boundaries","mermaid":"flowchart TD\\nB-->C"}]}'
        ),
        diagram_spec="flowchart TD\nA-->B",
        diagram_image=b'<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"><text>cached</text></svg>',
        tech_stack={"languages": ["python"], "frameworks": ["fastapi"]},
    )

    async def _fake_render(spec: str, llm_client=None, techs=None):
        return f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text>{spec}</text></svg>'.encode()

    monkeypatch.setattr(report_diagrams, "render_diagram_for_report", _fake_render)

    rendered = asyncio.run(report_diagrams.render_report_diagrams(report))

    assert len(rendered) == 2
    assert rendered[0].kind == "overview"
    assert b"cached" in rendered[0].image_bytes
    assert b"flowchart TD\nB-->C" in rendered[1].image_bytes
    assert rendered[1].media_type == "image/svg+xml"


def test_render_report_diagram_supports_indexed_on_demand_render(monkeypatch):
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        architecture=(
            '{"diagrams":['
            '{"title":"Overview","mermaid":"flowchart TD\\nA-->B"},'
            '{"title":"Trust","mermaid":"flowchart TD\\nB-->C"}]}'
        ),
        diagram_image=b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text>cached</text></svg>',
        tech_stack={"languages": ["python"]},
    )

    async def _fake_render(spec: str, llm_client=None, techs=None):
        return f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><text>{spec}</text></svg>'.encode()

    monkeypatch.setattr(report_diagrams, "render_diagram_for_report", _fake_render)

    rendered = asyncio.run(report_diagrams.render_report_diagram(report, 1))

    assert rendered is not None
    assert rendered.title == "Trust"
    assert b"flowchart TD\nB-->C" in rendered.image_bytes
    assert rendered.media_type == "image/svg+xml"


def test_backend_diagram_render_strips_icon_tokens_for_export(monkeypatch):
    captured: dict[str, str] = {}

    async def _fake_render(spec: str, *, config: str | None = None):
        captured["spec"] = spec
        return b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" height="120" viewBox="0 0 120 120"></svg>'

    monkeypatch.setattr(diagram_renderer, "render_mermaid_to_svg", _fake_render)

    rendered = asyncio.run(
        diagram_renderer.render_diagram_for_report(
            "flowchart TD\nA[fa:server API Backend]\nB[(mdi:database Postgres)]\nA --> B"
        )
    )

    assert b"<svg" in rendered
    assert "fa:server" not in captured["spec"]
    assert "mdi:database" not in captured["spec"]
    assert "API Backend" in captured["spec"]
    assert "Postgres" in captured["spec"]


def test_render_report_html_includes_narrative_explanation_and_fuller_poc():
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        app_summary="Application summary.",
        narrative="Security review narrative.",
        risk_grade="D",
        risk_score=72.0,
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=report.scan_id,
        title="SQL injection in login",
        severity="critical",
        confidence=0.95,
        category="injection",
        description="Description",
        explanation="Deeper analysis of why the sink is reachable.",
        impact="Impact",
        remediation="Remediation",
        exploit_difficulty="easy",
        exploit_prerequisites=["valid account"],
        exploit_template="\n".join(f"line {index}" for index in range(1, 9)),
        attack_scenario="Route or entry point: POST /login\n\nValidation:\n- observe delay",
    )
    html = _render_report_html(
        {
            "report": report,
            "findings": [finding],
            "secrets": [],
            "dep_findings": [],
            "diagrams": [
                RenderedReportDiagram(
                    title="Overview",
                    description="Primary diagram.",
                    image_bytes=b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>',
                    media_type="image/svg+xml",
                )
            ],
        }
    )

    assert "Security Review" in html
    assert "Deeper analysis of why the sink is reachable." in html
    assert "data:image/svg+xml;base64" in html
    assert "line 8" in html
    assert "Prerequisites:" in html


def test_render_report_html_includes_medium_exploit_appendix_details():
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        app_summary="Application summary.",
        narrative="Security review narrative.",
        risk_grade="C",
        risk_score=58.0,
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=report.scan_id,
        title="Export endpoint authorization gap",
        severity="medium",
        confidence=0.82,
        category="auth",
        description="The export endpoint allows low-privilege users to schedule exports.",
        explanation="Missing role enforcement on the export route.",
        exploit_evidence={
            "difficulty": "easy",
            "target_route": "POST /api/export",
            "prerequisites": ["authenticated low-privilege account"],
            "validation_steps": ["observe export job creation"],
            "cleanup_notes": ["delete the generated export artifact"],
            "exploit_template": "curl -X POST https://target/api/export",
            "attack_scenario": "Trigger a privileged export as a regular user.",
        },
    )

    html = _render_report_html(
        {
            "report": report,
            "findings": [finding],
            "secrets": [],
            "dep_findings": [],
            "diagrams": [],
        }
    )

    assert "Exploitable (PoC available):</strong> 1" in html
    assert "Exploit Evidence Appendix (1)" in html
    assert "POST /api/export" in html
    assert "observe export job creation" in html
    assert "delete the generated export artifact" in html
    assert "curl -X POST https://target/api/export" in html


def test_generate_docx_includes_medium_exploit_appendix_details(tmp_path):
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        app_summary="Application summary.",
        narrative="Security review narrative.",
        risk_grade="C",
        risk_score=58.0,
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=report.scan_id,
        title="Export endpoint authorization gap",
        severity="medium",
        confidence=0.82,
        category="auth",
        description="The export endpoint allows low-privilege users to schedule exports.",
        exploit_evidence={
            "difficulty": "easy",
            "target_route": "POST /api/export",
            "prerequisites": ["authenticated low-privilege account"],
            "validation_steps": ["observe export job creation"],
            "cleanup_notes": ["delete the generated export artifact"],
            "exploit_template": "curl -X POST https://target/api/export",
            "attack_scenario": "Trigger a privileged export as a regular user.",
        },
    )
    output_path = tmp_path / "report.docx"

    asyncio.run(
        _generate_docx(
            {
                "report": report,
                "findings": [finding],
                "secrets": [],
                "dep_findings": [],
                "diagrams": [],
            },
            output_path,
        )
    )

    with zipfile.ZipFile(output_path) as archive:
        xml = archive.read("word/document.xml").decode("utf-8")

    assert "Exploit Evidence Appendix" in xml
    assert "POST /api/export" in xml
    assert "observe export job creation" in xml
    assert "delete the generated export artifact" in xml
    assert "curl -X POST https://target/api/export" in xml


def test_verifier_exploit_eligibility_includes_deep_medium_and_is_not_capped(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.candidate_findings = [
        CandidateFinding(
            title=f"High finding {idx}",
            category="injection",
            severity="high",
            file_path=f"api/high_{idx}.py",
            confidence=0.65,
            status="confirmed",
        )
        for idx in range(10)
    ]
    ctx.candidate_findings.append(
        CandidateFinding(
            title="Critical auth bypass",
            category="auth",
            severity="critical",
            file_path="api/auth.py",
            confidence=0.56,
            status="confirmed",
        )
    )
    ctx.candidate_findings.append(
        CandidateFinding(
            title="Medium reachable issue",
            category="logic",
            severity="medium",
            file_path="api/logic.py",
            confidence=0.8,
            status="confirmed",
        )
    )

    eligible = VerifierAgent._eligible_exploit_evidence_findings(ctx, "deep")

    titles = {finding.title for finding in eligible}
    assert len(eligible) == 12
    assert "Critical auth bypass" in titles
    assert "Medium reachable issue" in titles
    assert "High finding 9" in titles


def test_sbom_payload_collapses_duplicate_dependency_rows():
    dep_id_a = uuid.uuid4()
    dep_id_b = uuid.uuid4()
    scan_id = uuid.uuid4()
    deps = [
        Dependency(
            id=dep_id_a,
            scan_id=scan_id,
            ecosystem="npm",
            name="lodash",
            version="4.17.20",
            source_file="package-lock.json",
            is_dev=False,
        ),
        Dependency(
            id=dep_id_b,
            scan_id=scan_id,
            ecosystem="npm",
            name="lodash",
            version="4.17.20",
            source_file="package-lock.json",
            is_dev=False,
        ),
    ]
    vulns = [
        DependencyFinding(
            dependency_id=dep_id_a,
            scan_id=scan_id,
            advisory_id="GHSA-1",
            cve_id="CVE-2020-8203",
            severity="high",
            summary="Prototype pollution",
            fixed_version="4.17.21",
        ),
        DependencyFinding(
            dependency_id=dep_id_b,
            scan_id=scan_id,
            advisory_id="GHSA-2",
            cve_id="CVE-2021-23337",
            severity="medium",
            summary="Command injection",
            fixed_version="4.17.21",
        ),
    ]

    sbom = ReporterAgent._build_sbom_payload(deps, vulns)

    assert sbom["total_components"] == 1
    assert sbom["vulnerable_components"] == 1
    assert sbom["components"][0]["name"] == "lodash"
    assert sbom["components"][0]["vulnerability_count"] == 2


def test_render_report_html_includes_phase4_export_sections():
    scan_id = uuid.uuid4()
    report = Report(
        id=uuid.uuid4(),
        scan_id=scan_id,
        app_summary="Application summary.",
        narrative="Security review narrative.",
        risk_grade="D",
        risk_score=72.0,
        architecture=json.dumps(
            {
                "attack_surface": ["api/routes.py::login POST /login"],
                "entry_points": [
                    {
                        "file": "api/routes.py",
                        "function": "login",
                        "method": "POST",
                        "path": "/login",
                        "type": "http_endpoint",
                    }
                ],
                "trust_boundaries": ["Public API boundary"],
            }
        ),
        sbom={
            "total_components": 2,
            "vulnerable_components": 1,
            "ecosystems": {"npm": 2},
            "components": [
                {
                    "name": "lodash",
                    "version": "4.17.20",
                    "ecosystem": "npm",
                    "is_dev": False,
                    "vulnerable": True,
                    "vulnerability_count": 2,
                },
                {
                    "name": "react",
                    "version": "18.2.0",
                    "ecosystem": "npm",
                    "is_dev": False,
                    "vulnerable": False,
                    "vulnerability_count": 0,
                },
            ],
        },
        scan_coverage={
            "total_files": 120,
            "files_indexed": 114,
            "files_inspected_by_ai": 18,
            "ai_calls_made": 12,
            "scan_mode": "deep",
            "scanners_used": ["semgrep", "bandit"],
            "degraded_coverage": True,
            "is_monorepo": True,
            "obfuscated_files": 3,
            "doc_files_read": 4,
            "has_doc_intelligence": True,
            "ignored_file_count": 9,
            "scanner_runs": {
                "semgrep": {"scanner": "semgrep", "status": "completed", "hit_count": 8, "errors": []},
                "bandit": {"scanner": "bandit", "status": "degraded", "hit_count": 2, "errors": ["partial parse failure"]},
            },
            "scanner_availability": {"bandit": "available", "codeql": "missing"},
            "managed_paths_ignored": ["node_modules"],
            "ignored_paths": [".git", "dist"],
            "repo_ignore_file": ".vrignore",
        },
        tech_stack={
            "fingerprint": {
                "languages": [
                    {"name": "python", "file_count": 10},
                    {"name": "typescript", "file_count": 6},
                ]
            }
        },
        scanner_hits={"semgrep": 8, "bandit": 2},
        attack_surface={"auth": 3, "data": 2, "network": 4},
    )
    chain_finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        title="Privilege escalation exploit chain",
        severity="high",
        confidence=0.88,
        category="exploit_chain",
        description="A missing auth check and unsafe queue consumer can be chained.",
        impact="Admin export and downstream data disclosure.",
    )
    chain_finding.evidence = [
        Evidence(type="supporting", description="Authenticate as a low-privilege user."),
        Evidence(type="supporting", description="Invoke POST /login to obtain a valid session."),
        Evidence(type="supporting", description="Trigger POST /api/export to enqueue an admin-scoped export."),
    ]
    html = _render_report_html(
        {
            "report": report,
            "findings": [chain_finding],
            "secrets": [],
            "dep_findings": [],
            "diagrams": [],
        }
    )

    assert "Concrete Attack Surface" in html
    assert "POST /login in api/routes.py::login [http_endpoint]" in html
    assert "Public API boundary" in html
    assert "Exploit Chains (1)" in html
    assert "Trigger POST /api/export to enqueue an admin-scoped export." in html
    assert "Software Bill Of Materials" in html
    assert "lodash" in html
    assert "Coverage notes:" in html
    assert "Scanner run status:" in html
    assert "Scanner availability:" in html


def test_golden_report_fixture_renders_stable_html_and_docx_sections(tmp_path):
    report_data = _load_golden_report_fixture()

    html = _render_report_html(report_data)
    assert "Security Assessment Report" in html
    assert "Concrete Attack Surface" in html
    assert "POST /api/export in api/routes.py::export_data [http_endpoint]" in html
    assert "Exploit Chains (1)" in html
    assert "Read the resulting export artifact." in html
    assert "Exploit Evidence Appendix (1)" in html
    assert "curl -X POST https://target/api/export" in html
    assert "Dependency Risks (1)" in html
    assert "Reached from the export worker path." in html
    assert "Software Bill Of Materials" in html
    assert "Verified Security Overview" in html
    assert "data:image/svg+xml;base64" in html

    output_path = tmp_path / "golden-report.docx"
    asyncio.run(_generate_docx(report_data, output_path))

    with zipfile.ZipFile(output_path) as archive:
        xml = archive.read("word/document.xml").decode("utf-8")

    assert "Exploit Chains" in xml
    assert "Privilege escalation exploit chain" in xml
    assert "Dependency Risks" in xml
    assert "Software Bill Of Materials" in xml
    assert "Exploit Evidence Appendix" in xml
    assert "curl -X POST https://target/api/export" in xml
    assert "Repo ignore file:" in html


def test_generate_docx_includes_phase4_sections(tmp_path):
    scan_id = uuid.uuid4()
    report = Report(
        id=uuid.uuid4(),
        scan_id=scan_id,
        app_summary="Application summary.",
        narrative="Security review narrative.",
        risk_grade="D",
        risk_score=72.0,
        architecture=json.dumps(
            {
                "entry_points": [
                    {
                        "file": "api/routes.py",
                        "function": "login",
                        "method": "POST",
                        "path": "/login",
                        "type": "http_endpoint",
                    }
                ],
                "trust_boundaries": ["Public API boundary"],
            }
        ),
        sbom={
            "total_components": 1,
            "vulnerable_components": 1,
            "ecosystems": {"npm": 1},
            "components": [
                {
                    "name": "lodash",
                    "version": "4.17.20",
                    "ecosystem": "npm",
                    "is_dev": False,
                    "vulnerable": True,
                    "vulnerability_count": 2,
                }
            ],
        },
        scan_coverage={
            "total_files": 12,
            "files_indexed": 11,
            "files_inspected_by_ai": 5,
            "ai_calls_made": 4,
            "scan_mode": "deep",
            "scanners_used": ["semgrep"],
            "degraded_coverage": True,
            "doc_files_read": 2,
            "has_doc_intelligence": True,
            "scanner_runs": {
                "semgrep": {"scanner": "semgrep", "status": "degraded", "hit_count": 3, "errors": ["timeout"]}
            },
            "scanner_availability": {"semgrep": "available"},
            "repo_ignore_file": ".vrignore",
        },
    )
    chain_finding = Finding(
        id=uuid.uuid4(),
        scan_id=scan_id,
        title="Privilege escalation exploit chain",
        severity="high",
        confidence=0.88,
        category="exploit_chain",
        description="A missing auth check and unsafe queue consumer can be chained.",
    )
    chain_finding.evidence = [
        Evidence(type="supporting", description="Authenticate as a low-privilege user."),
        Evidence(type="supporting", description="Invoke POST /api/export."),
    ]
    output_path = tmp_path / "phase4-report.docx"

    asyncio.run(
        _generate_docx(
            {
                "report": report,
                "findings": [chain_finding],
                "secrets": [],
                "dep_findings": [],
                "diagrams": [],
            },
            output_path,
        )
    )

    with zipfile.ZipFile(output_path) as archive:
        xml = archive.read("word/document.xml").decode("utf-8")

    assert "Concrete Attack Surface" in xml
    assert "POST /login in api/routes.py::login [http_endpoint]" in xml
    assert "Exploit Chains" in xml
    assert "Invoke POST /api/export." in xml
    assert "Software Bill Of Materials" in xml
    assert "lodash" in xml
    assert "Coverage notes" in xml
    assert "Scanner run status" in xml
    assert "Scanner availability" in xml
    assert ".vrignore" in xml


def test_generate_export_persists_report_html_for_export_source(tmp_path, monkeypatch):
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        app_summary="Application summary.",
        narrative="Security review narrative.",
        risk_grade="C",
        risk_score=58.0,
        architecture=json.dumps(
            {
                "entry_points": [
                    {
                        "file": "api/routes.py",
                        "function": "login",
                        "method": "POST",
                        "path": "/login",
                        "type": "http_endpoint",
                    }
                ]
            }
        ),
    )
    finding = Finding(
        id=uuid.uuid4(),
        scan_id=report.scan_id,
        title="Export endpoint authorization gap",
        severity="medium",
        confidence=0.82,
        category="auth",
        description="The export endpoint allows low-privilege users to schedule exports.",
    )

    class _ScalarResult:
        def __init__(self, items):
            self._items = items

        def scalars(self):
            return self

        def all(self):
            return self._items

    class _RowsResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _FakeDb:
        def __init__(self):
            self._calls = 0
            self.added = []

        async def execute(self, _stmt):
            self._calls += 1
            if self._calls == 1:
                return _ScalarResult([finding])
            if self._calls == 2:
                return _ScalarResult([])
            if self._calls == 3:
                return _RowsResult([])
            raise AssertionError("unexpected execute call")

        def add(self, obj):
            self.added.append(obj)

        async def flush(self):
            return None

    fake_db = _FakeDb()
    captured: dict[str, str] = {}

    async def _fake_render_report_diagrams(_report):
        return []

    async def _fake_generate_pdf(data, output_path):
        captured["report_html"] = data["report_html"]
        output_path.write_bytes(b"%PDF-1.4")

    monkeypatch.setattr(export_service, "render_report_diagrams", _fake_render_report_diagrams)
    monkeypatch.setattr(export_service, "_generate_pdf", _fake_generate_pdf)
    monkeypatch.setattr(export_service.settings, "export_dir", tmp_path)

    artifact = asyncio.run(generate_export(report, "pdf", fake_db))

    assert artifact.format == "pdf"
    assert report.report_html is not None
    assert "Concrete Attack Surface" in report.report_html
    assert captured["report_html"] == report.report_html
    assert fake_db.added[0] is artifact


def test_generate_export_resolves_secret_file_paths(tmp_path, monkeypatch):
    report = Report(
        id=uuid.uuid4(),
        scan_id=uuid.uuid4(),
        app_summary="Application summary.",
        narrative="Security review narrative.",
        risk_grade="C",
        risk_score=58.0,
    )
    file_id = uuid.uuid4()
    secret = SecretCandidate(
        id=uuid.uuid4(),
        scan_id=report.scan_id,
        file_id=file_id,
        type="api_key",
        confidence=0.97,
        is_false_positive=False,
    )

    class _ScalarResult:
        def __init__(self, items):
            self._items = items

        def scalars(self):
            return self

        def all(self):
            return self._items

    class _RowsResult:
        def __init__(self, rows):
            self._rows = rows

        def all(self):
            return self._rows

    class _FakeDb:
        def __init__(self):
            self._calls = 0
            self.added = []

        async def execute(self, _stmt):
            self._calls += 1
            if self._calls == 1:
                return _ScalarResult([])
            if self._calls == 2:
                return _ScalarResult([secret])
            if self._calls == 3:
                return _RowsResult([SimpleNamespace(id=file_id, path="config/secrets.php")])
            if self._calls == 4:
                return _RowsResult([])
            raise AssertionError("unexpected execute call")

        def add(self, obj):
            self.added.append(obj)

        async def flush(self):
            return None

    fake_db = _FakeDb()
    captured: dict[str, object] = {}

    async def _fake_render_report_diagrams(_report):
        return []

    async def _fake_generate_pdf(data, output_path):
        captured["secrets"] = data["secrets"]
        output_path.write_bytes(b"%PDF-1.4")

    monkeypatch.setattr(export_service, "render_report_diagrams", _fake_render_report_diagrams)
    monkeypatch.setattr(export_service, "_generate_pdf", _fake_generate_pdf)
    monkeypatch.setattr(export_service.settings, "export_dir", tmp_path)

    artifact = asyncio.run(generate_export(report, "pdf", fake_db))

    assert artifact.format == "pdf"
    assert captured["secrets"][0].file_path == "config/secrets.php"
    assert "config/secrets.php" in report.report_html


def test_generate_pdf_falls_back_when_weasyprint_runtime_is_unavailable(tmp_path, monkeypatch):
    output_path = tmp_path / "fallback.pdf"
    report = Report(id=uuid.uuid4(), scan_id=uuid.uuid4(), app_summary="Summary")
    called = {"fallback": False}
    original_import = builtins.__import__

    async def fake_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)

    def fake_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise OSError("missing gobject runtime")
        return original_import(name, *args, **kwargs)

    def fake_reportlab(data, path):
        called["fallback"] = True
        path.write_bytes(b"%PDF-1.4 fallback")

    monkeypatch.setattr("asyncio.to_thread", fake_to_thread)
    monkeypatch.setattr(export_service, "_generate_pdf_with_reportlab", fake_reportlab)
    monkeypatch.setattr(builtins, "__import__", fake_import)

    asyncio.run(
        _generate_pdf(
            {
                "report": report,
                "findings": [],
                "secrets": [],
                "dep_findings": [],
                "report_html": "<html><body>fallback</body></html>",
            },
            output_path,
        )
    )

    assert called["fallback"] is True
    assert output_path.read_bytes().startswith(b"%PDF-1.4")
