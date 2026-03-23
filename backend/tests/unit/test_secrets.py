"""Tests for secrets scanner."""

import pytest

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
