import uuid
from types import SimpleNamespace

from app.orchestrator.agents.rule_selector import RuleSelectorAgent


def test_rule_selector_optimises_semgrep_dirs(monkeypatch, tmp_path):
    rules_root = tmp_path / "semgrep-rules"
    for relative in (
        "javascript/lang",
        "javascript/express",
        "javascript/browser",
        "dockerfile/security",
        "dockerfile/audit",
        "python/lang",
        "ruby/lang",
    ):
        (rules_root / relative).mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("app.orchestrator.agents.rule_selector.settings.semgrep_rules_dir", rules_root)
    monkeypatch.setattr("app.orchestrator.agents.rule_selector.os.name", "nt")

    agent = RuleSelectorAgent(llm=SimpleNamespace())
    ctx = SimpleNamespace(
        languages=["python", "typescript"],
        frameworks=["react", "express"],
        baseline_rule_dirs=["python/lang", "javascript/lang", "dockerfile/security"],
        baseline_rule_count=0,
    )

    optimised = agent._optimise_semgrep_dirs(
        ctx,
        ["python", "javascript", "dockerfile", "javascript/express", "generic", "ruby"],
    )

    assert optimised == [
        "javascript/browser",
        "javascript/express",
        "dockerfile/audit",
    ]
