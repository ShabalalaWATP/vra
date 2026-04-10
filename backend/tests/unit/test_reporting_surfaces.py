"""Tests for reporting payloads and advisory reporting surfaces."""

import uuid

from app.models.dependency import Dependency, DependencyFinding
from app.orchestrator.agents.reporter import ReporterAgent
from app.orchestrator.agents.verifier import VerifierAgent
from app.orchestrator.scan_context import CandidateFinding, ScanContext
from app.services.export_service import _format_related_advisories


def _ctx(tmp_path) -> ScanContext:
    return ScanContext(
        scan_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        repo_path=str(tmp_path),
        mode="regular",
    )


def test_reporter_build_architecture_payload_adds_result_aware_diagrams(tmp_path):
    ctx = _ctx(tmp_path)
    ctx.architecture_notes = (
        '{"components":[{"name":"API","files":["api"],"criticality":"critical","in_attack_surface":true}],'
        '"auth_mechanisms":[{"type":"jwt","implementation":"api/auth.py"}],'
        '"external_integrations":["postgres"],'
        '"diagrams":[{"title":"System Overview","description":"legacy","mermaid":"flowchart TD\\n    A[fa:server API]"}]}'
    )
    ctx.trust_boundaries = ["Public HTTP boundary"]
    ctx.entry_points = [{"file": "api/routes.py", "function": "login", "path": "/login"}]
    ctx.candidate_findings = [
        CandidateFinding(
            title="Command injection in admin task runner",
            category="command_exec",
            severity="critical",
            file_path="api/tasks.py",
            confidence=0.92,
            status="confirmed",
            related_cves=[{"display_id": "CVE-2026-1000", "summary": "unsafe call", "severity": "high", "package": "pyyaml"}],
        ),
        CandidateFinding(
            title="Weak access control on export endpoint",
            category="auth",
            severity="high",
            file_path="api/routes.py",
            confidence=0.81,
            status="confirmed",
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

    assert payload["result_summary"]["finding_count"] == 2
    assert payload["result_summary"]["critical_count"] == 1
    assert payload["result_summary"]["advisory_correlated_count"] == 1
    assert payload["result_summary"]["reachable_dependency_count"] == 1
    assert payload["component_hotspots"][0]["name"] == "API"
    assert payload["diagrams"][0]["title"] == "Verified Security Overview"
    assert any(diagram["title"] == "Dependency Exposure And Reachability" for diagram in payload["diagrams"])
    assert any("reachable dependency risks" in highlight for highlight in payload["diagrams"][0]["highlights"])


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
