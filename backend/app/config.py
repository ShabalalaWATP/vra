import os
import sysconfig
from pathlib import Path

from pydantic_settings import BaseSettings

# Ensure Python user scripts directory is on PATH (for pip install --user binaries)
_user_scripts = sysconfig.get_path("scripts", f"{os.name}_user")
if _user_scripts and os.path.isdir(_user_scripts) and _user_scripts not in os.environ.get("PATH", ""):
    os.environ["PATH"] = _user_scripts + os.pathsep + os.environ.get("PATH", "")


class Settings(BaseSettings):
    model_config = {"env_prefix": "VRAGENT_"}

    # Database
    database_url: str = "postgresql+asyncpg://vragent:vragent@localhost:5432/vragent"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    cors_origins: str = "http://localhost:3000,http://localhost:5173"  # Comma-separated

    # Paths
    data_dir: Path = Path(__file__).parent.parent / "data"
    upload_dir: Path = Path(__file__).parent.parent / "uploads"
    export_dir: Path = Path(__file__).parent.parent / "exports"

    # Scanner paths (override if installed elsewhere)
    semgrep_binary: str = "semgrep"
    bandit_binary: str = "bandit"
    eslint_binary: str = "eslint"
    codeql_binary: str = str(
        Path(__file__).parent.parent / "tools" / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")
    )
    jadx_binary: str = "jadx"  # APK decompiler

    # Semgrep rules
    semgrep_rules_dir: Path | None = None

    # Advisory DB
    advisory_db_dir: Path | None = None

    # Scan defaults
    default_scan_mode: str = "regular"
    max_file_size_bytes: int = 1_000_000  # 1MB
    max_files_per_scan: int = 10_000

    @property
    def semgrep_rules_path(self) -> Path:
        return self.semgrep_rules_dir or self.data_dir / "semgrep-rules"

    @property
    def advisory_db_path(self) -> Path:
        return self.advisory_db_dir or self.data_dir / "advisories"


settings = Settings()
