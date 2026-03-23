"""Tests for file scoring."""

from app.analysis.file_scorer import score_file


def test_auth_file_scores_high():
    score, reasons = score_file("src/auth/login_handler.py", language="python", line_count=100)
    assert score > 20


def test_test_file_scores_lower():
    score, reasons = score_file("tests/test_auth.py", language="python", line_count=50)
    auth_score, _ = score_file("src/auth.py", language="python", line_count=50)
    assert score < auth_score


def test_scanner_hits_boost():
    base_score, _ = score_file("src/handler.py", language="python", line_count=100)
    boosted_score, _ = score_file(
        "src/handler.py", language="python", line_count=100, scanner_hit_count=5
    )
    assert boosted_score > base_score
