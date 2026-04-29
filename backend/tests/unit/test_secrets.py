"""Tests for secrets scanner."""

import uuid

import pytest

from app.orchestrator.agents.verifier import VerifierAgent
from app.orchestrator.scan_context import CandidateFinding, ScanContext
from app.scanners.secrets import SecretsScanner


@pytest.mark.asyncio
async def test_secrets_scanner_detects_keys(sample_repo):
    scanner = SecretsScanner()
    result = await scanner.run(sample_repo)
    assert result.success
    # Should detect the SECRET_KEY and DATABASE_URL
    assert len(result.hits) >= 1

    types_found = {h.metadata.get("type") for h in result.hits}
    assert "secret" in types_found or "connection_string" in types_found


@pytest.mark.asyncio
async def test_secrets_scanner_ignores_common_placeholder_values(tmp_path):
    (tmp_path / "settings.py").write_text(
        'PASSWORD = "password"\n'
        'SECRET_KEY = "changeme"\n'
        'TOKEN = "${TOKEN}"\n'
        'API_KEY = "<API_KEY>"\n'
        'CLIENT_SECRET = "not_a_secret"\n',
        encoding="utf-8",
    )

    result = await SecretsScanner().run(tmp_path)

    assert result.success
    assert result.hits == []


def _ctx(tmp_path) -> ScanContext:
    return ScanContext(
        scan_id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        repo_path=str(tmp_path),
        mode="regular",
    )


def test_verifier_dismisses_placeholder_secret_findings(tmp_path):
    ctx = _ctx(tmp_path)
    finding = CandidateFinding(
        title="Hardcoded password",
        category="secrets",
        severity="critical",
        file_path=".env.example",
        code_snippet='PASSWORD = "password"',
        hypothesis="A hardcoded password value was found.",
        confidence=0.95,
        status="confirmed",
        source_scanners=["secrets"],
        source_rules=["secrets/secret"],
    )
    ctx.candidate_findings = [finding]

    canonical_count, _merged_count = VerifierAgent(llm=None)._finalise_verified_findings(ctx)

    assert canonical_count == 0
    assert finding.status == "dismissed"
    assert finding.severity == "info"
    assert "placeholder/example" in finding.verification_notes


def test_verifier_downgrades_isolated_data_flow_findings_without_context(tmp_path):
    ctx = _ctx(tmp_path)
    finding = CandidateFinding(
        title="Potential SQL injection pattern",
        category="injection",
        severity="critical",
        file_path="app/models.py",
        hypothesis="String formatting appears near a SQL execute call.",
        confidence=0.92,
        status="confirmed",
        verification_level="statically_verified",
    )
    ctx.candidate_findings = [finding]

    canonical_count, _merged_count = VerifierAgent(llm=None)._finalise_verified_findings(ctx)

    assert canonical_count == 1
    assert finding.status == "confirmed"
    assert finding.severity == "medium"
    assert finding.confidence == 0.6
    assert "No explicit attacker-controlled source" in finding.verification_notes
