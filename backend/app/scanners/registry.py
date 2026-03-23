"""Scanner registry — creates fresh scanner instances per scan.

Each scan gets its own scanner instances to avoid shared mutable state
(e.g., CodeQL's database cache, DepAudit's advisory index) from
interfering between concurrent scans.
"""

from app.scanners.bandit import BanditAdapter
from app.scanners.base import ScannerAdapter
from app.scanners.codeql import CodeQLAdapter
from app.scanners.dep_audit import DepAuditAdapter
from app.scanners.eslint import ESLintAdapter
from app.scanners.secrets import SecretsScanner
from app.scanners.semgrep import SemgrepAdapter


def create_scanner_set() -> dict[str, ScannerAdapter]:
    """Create a fresh set of scanner instances (one per scan)."""
    return {
        "semgrep": SemgrepAdapter(),
        "bandit": BanditAdapter(),
        "eslint": ESLintAdapter(),
        "codeql": CodeQLAdapter(),
        "secrets": SecretsScanner(),
        "dep_audit": DepAuditAdapter(),
    }


def get_scanner(name: str) -> ScannerAdapter | None:
    """Get a fresh scanner instance by name."""
    return create_scanner_set().get(name)


def get_all_scanners() -> dict[str, ScannerAdapter]:
    """Create a fresh set of all scanners."""
    return create_scanner_set()


async def get_available_scanners() -> dict[str, ScannerAdapter]:
    """Return only scanners that are currently available on this system.

    Creates fresh instances so they can be used safely per-scan.
    """
    scanners = create_scanner_set()
    available = {}
    for name, scanner in scanners.items():
        if await scanner.is_available():
            available[name] = scanner
    return available
