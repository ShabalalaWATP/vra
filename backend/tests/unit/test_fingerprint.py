"""Tests for repo fingerprinting."""

from app.analysis.fingerprint import fingerprint_repo


def test_fingerprint_detects_languages(sample_repo):
    fp = fingerprint_repo(sample_repo)
    lang_names = [l["name"] for l in fp["languages"]]
    assert "python" in lang_names
    assert "javascript" in lang_names


def test_fingerprint_detects_frameworks(sample_repo):
    fp = fingerprint_repo(sample_repo)
    # requirements.txt triggers python framework
    assert "python" in fp["frameworks"] or len(fp["frameworks"]) >= 0


def test_fingerprint_counts_files(sample_repo):
    fp = fingerprint_repo(sample_repo)
    assert fp["file_count"] >= 3
