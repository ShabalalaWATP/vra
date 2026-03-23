"""Base scanner adapter interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScannerHit:
    """Normalized scanner result."""

    rule_id: str
    severity: str  # critical, high, medium, low, info
    message: str
    file_path: str
    start_line: int
    end_line: int | None = None
    snippet: str | None = None
    metadata: dict = field(default_factory=dict)


@dataclass
class ScannerOutput:
    """Result of running a scanner."""

    scanner_name: str
    success: bool
    hits: list[ScannerHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0


class ScannerAdapter(ABC):
    """Abstract base for all scanner integrations."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner identifier."""
        ...

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the scanner binary/tool is installed and reachable."""
        ...

    @abstractmethod
    async def get_version(self) -> str | None:
        """Return the scanner version string, or None if unavailable."""
        ...

    @abstractmethod
    async def run(
        self,
        target_path: Path,
        *,
        languages: list[str] | None = None,
        rules: list[str] | None = None,
        file_filter: list[str] | None = None,
    ) -> ScannerOutput:
        """
        Run the scanner against a target directory or file list.

        Args:
            target_path: Root directory to scan
            languages: Filter to specific languages
            rules: Specific rule IDs or rule groups to apply
            file_filter: Only scan these specific file paths
        """
        ...

    @abstractmethod
    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        """
        Run the scanner on specific files with specific rules.
        Used for targeted follow-up during investigation.
        """
        ...
