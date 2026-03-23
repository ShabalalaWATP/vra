"""Secrets and sensitive data scanner — regex + entropy-based offline detection.

Improvements over a naive regex-only approach:
- Shannon entropy analysis to filter out low-entropy false positives
- Filename-based confidence adjustment (test files lower, config files higher)
- Context-aware filtering (known false positive patterns)
- 40+ secret patterns covering cloud providers, SaaS platforms, and protocols
"""

import logging
import math

logger = logging.getLogger(__name__)
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from app.scanners.base import ScannerAdapter, ScannerHit, ScannerOutput

# ── Pattern definitions ──────────────────────────────────────────
# (name, type, regex, base_confidence, min_entropy)
# min_entropy: the matched value must have at least this Shannon entropy
#              to be considered a real secret (0 = skip entropy check)
SECRET_PATTERNS: list[tuple[str, str, str, float, float]] = [
    # ── Cloud Provider Keys ──────────────────────────────────────
    ("AWS Access Key", "aws_key", r"AKIA[0-9A-Z]{16}", 0.95, 0),
    ("AWS Secret Key", "aws_secret", r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})", 0.9, 3.5),
    ("Azure Storage Key", "azure_key", r"(?i)(AccountKey|azure[_-]?storage[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{44,})", 0.85, 3.5),
    ("Azure Client Secret", "azure_secret", r"(?i)azure[_-]?client[_-]?secret\s*[=:]\s*['\"]?([A-Za-z0-9~._-]{34,})", 0.85, 3.5),
    ("GCP Service Account Key", "gcp_key", r'"private_key"\s*:\s*"-----BEGIN', 0.95, 0),
    ("GCP/Firebase API Key", "gcp_api_key", r"AIza[0-9A-Za-z_-]{35}", 0.9, 0),
    # ── SaaS / Platform Tokens ───────────────────────────────────
    ("GitHub Token", "github_token", r"gh[pousr]_[A-Za-z0-9_]{36,}", 0.95, 0),
    ("GitHub Fine-Grained PAT", "github_fine_pat", r"github_pat_[A-Za-z0-9_]{22,}", 0.95, 0),
    ("GitLab Token", "gitlab_token", r"glpat-[A-Za-z0-9_-]{20,}", 0.95, 0),
    ("Slack Token", "slack_token", r"xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+", 0.9, 0),
    ("Slack Webhook", "slack_webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", 0.9, 0),
    ("Discord Token", "discord_token", r"(?i)(discord[_-]?token|bot[_-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9._-]{50,})", 0.8, 3.5),
    ("Discord Webhook", "discord_webhook", r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+", 0.9, 0),
    ("Stripe Secret Key", "stripe_secret", r"sk_live_[A-Za-z0-9]{24,}", 0.95, 0),
    ("Stripe Publishable Key", "stripe_pub", r"pk_live_[A-Za-z0-9]{24,}", 0.7, 0),
    ("Twilio API Key", "twilio_key", r"SK[0-9a-fA-F]{32}", 0.85, 3.0),
    ("SendGrid API Key", "sendgrid_key", r"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}", 0.9, 0),
    ("Mailgun API Key", "mailgun_key", r"key-[0-9a-zA-Z]{32}", 0.85, 3.0),
    ("NPM Token", "npm_token", r"npm_[A-Za-z0-9]{36}", 0.9, 0),
    ("PyPI Token", "pypi_token", r"pypi-[A-Za-z0-9_-]{50,}", 0.9, 0),
    ("NuGet API Key", "nuget_key", r"oy2[a-z0-9]{43}", 0.85, 0),
    ("Heroku API Key", "heroku_key", r"(?i)heroku[_-]?api[_-]?key\s*[=:]\s*['\"]?([0-9a-fA-F-]{36})", 0.85, 3.0),
    ("Datadog API Key", "datadog_key", r"(?i)dd[_-]?api[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{32})", 0.8, 3.5),
    ("New Relic Key", "newrelic_key", r"NRAK-[A-Z0-9]{27}", 0.9, 0),
    ("Sentry DSN", "sentry_dsn", r"https://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/\d+", 0.85, 0),
    # ── Generic Secrets ──────────────────────────────────────────
    ("Generic API Key", "api_key", r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]", 0.7, 3.5),
    ("Generic Secret", "secret", r"(?i)(secret(?:[_-]?key)?|token|password|passwd|pwd|client[_-]?secret)\s*[=:]\s*['\"]([^\s'\"]{8,})['\"]", 0.6, 3.0),
    ("Generic Auth Header", "auth_header", r"(?i)(authorization|bearer)\s*[=:]\s*['\"]([A-Za-z0-9._\-]{20,})['\"]", 0.65, 3.0),
    # ── JWT / Bearer ─────────────────────────────────────────────
    ("Bearer Token", "bearer_token", r"(?i)bearer\s+[a-zA-Z0-9_\-.~+/]+=*", 0.7, 0),
    ("JWT Token", "jwt", r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_\-]+", 0.85, 0),
    # ── SSH / Crypto ─────────────────────────────────────────────
    ("RSA Private Key", "private_key", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 0.95, 0),
    ("PGP Private Key", "pgp_key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----", 0.95, 0),
    ("SSH Key", "ssh_key", r"ssh-(rsa|ed25519|dss|ecdsa)\s+[A-Za-z0-9+/]{40,}", 0.8, 0),
    # ── Connection Strings ───────────────────────────────────────
    ("DB Connection String", "connection_string", r"(?i)(postgres(?:ql)?|mysql|mongodb|redis|mssql|sqlserver)://[^\s'\"]+", 0.8, 0),
    ("JDBC URL", "jdbc_url", r"jdbc:[a-z]+://[^\s'\"]+@[^\s'\"]+", 0.75, 0),
    ("AMQP URL", "amqp_url", r"amqps?://[^\s'\"]+", 0.7, 0),
    ("SMTP Credentials", "smtp_creds", r"(?i)smtp[_-]?pass(word)?\s*[=:]\s*['\"]([^\s'\"]{6,})['\"]", 0.7, 3.0),
    # ── Network / URLs ───────────────────────────────────────────
    ("Internal URL", "internal_url", r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|localhost)[:\w/\-]*", 0.5, 0),
    ("Hardcoded IP", "hardcoded_ip", r"(?<!\d)(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?!\d)", 0.4, 0),
    # ── Kubernetes / Docker ──────────────────────────────────────
    ("K8s Service Account Token", "k8s_token", r"/var/run/secrets/kubernetes\.io/serviceaccount/token", 0.7, 0),
    ("Docker Registry Auth", "docker_auth", r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"', 0.75, 3.0),
    # ── Android / Mobile ──────────────────────────────────────────
    # Firebase API Key uses same AIza pattern as GCP — already covered by gcp_api_key above
    ("Firebase Server Key", "firebase_server_key", r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", 0.9, 0),
    ("Google OAuth Client ID", "google_oauth", r"\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com", 0.7, 0),
    ("Android Keystore Password", "keystore_pass", r"(?i)(storePassword|keyPassword|key\.store\.password|key\.alias\.password)\s*[=:]\s*['\"]?([^\s'\"]{4,})", 0.8, 2.5),
    ("Android Signing Key", "signing_key", r"(?i)(signingConfig|release\s*\{[^}]*storeFile)", 0.6, 0),
    ("Google Services JSON", "google_services", r'"api_key"\s*:\s*\[\s*\{\s*"current_key"\s*:', 0.9, 0),
    ("FCM/GCM Server Key", "fcm_key", r"(?i)(fcm[_-]?server[_-]?key|gcm[_-]?api[_-]?key)\s*[=:]\s*['\"]?([A-Za-z0-9_-]{30,})", 0.85, 3.0),
    ("Android Debug Keystore", "debug_keystore", r"(?i)debug\.keystore|\.android/debug\.keystore", 0.5, 0),
    ("Hardcoded App Secret", "app_secret", r"(?i)(app[_-]?secret|client[_-]?secret)\s*[=:]\s*['\"]([A-Za-z0-9_-]{16,})['\"]", 0.7, 3.0),
]

# ── False positive patterns ──────────────────────────────────────
# Values matching these are likely placeholders, not real secrets
FALSE_POSITIVE_PATTERNS = [
    re.compile(r"(?i)^(example|test|demo|sample|dummy|fake|placeholder|your[_-]?|my[_-]?|xxx|changeme|replace|todo|fixme)"),
    re.compile(r"(?i)^(password|secret|key|token|api_key|none|null|undefined|empty|default|insert)$"),
    re.compile(r"^[a-zA-Z]+$"),  # All letters, no numbers/symbols — unlikely to be a real secret
    re.compile(r"^\*+$"),  # All asterisks
    re.compile(r"^\.{3,}$"),  # All dots
    re.compile(r"^<[^>]+>$"),  # XML-style placeholder like <YOUR_KEY>
    re.compile(r"^\$\{.+\}$"),  # Template variable like ${API_KEY}
    re.compile(r"^%\(.+\)s$"),  # Python format like %(api_key)s
]

# ── High-confidence files (boost score) ──────────────────────────
HIGH_CONFIDENCE_FILES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "credentials.json", "service-account.json", "secrets.yaml",
    "secrets.yml", ".netrc", ".pgpass", ".npmrc", ".pypirc",
    "docker-compose.yml", "docker-compose.yaml",
}

# ── Low-confidence files (reduce score) ──────────────────────────
LOW_CONFIDENCE_FILES = {
    "test", "spec", "mock", "fixture", "example", "sample",
    "readme", "changelog", "contributing", "license",
    "documentation", "docs", ".md",
}

# Files to skip entirely
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".wav", ".avi", ".mkv", ".mov",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".bin", ".exe", ".dll", ".so", ".dylib",
    ".pyc", ".pyo", ".class", ".o", ".obj",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".sqlite", ".db", ".sqlite3", ".wasm",
    ".lock", ".min.js", ".min.css", ".map",
}

SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "dist",
    "build", ".next", "target", "vendor", ".tox",
}


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def is_false_positive(value: str) -> bool:
    """Check if a matched value is a known false positive pattern."""
    clean = value.strip("'\" \t")
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.match(clean):
            return True
    return False


def _extract_secret_value(match: re.Match[str]) -> str:
    """Return the capture group most likely to contain the actual secret."""
    if not match.lastindex:
        return match.group(0)

    for index in range(match.lastindex, 0, -1):
        value = match.group(index)
        if value:
            return value

    return match.group(0)


class SecretsScanner(ScannerAdapter):
    @property
    def name(self) -> str:
        return "secrets"

    async def is_available(self) -> bool:
        return True

    async def get_version(self) -> str | None:
        return "2.0.0"

    async def run(
        self,
        target_path: Path,
        *,
        languages: list[str] | None = None,
        rules: list[str] | None = None,
        file_filter: list[str] | None = None,
    ) -> ScannerOutput:
        start = time.monotonic()
        hits = []

        if file_filter:
            files = [target_path / f for f in file_filter]
        else:
            files = self._collect_files(target_path)

        compiled = [
            (name, stype, re.compile(pattern), conf, min_ent)
            for name, stype, pattern, conf, min_ent in SECRET_PATTERNS
        ]

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(target_path)).replace("\\", "/")

                # Adjust confidence based on filename
                file_confidence_mult = self._file_confidence_multiplier(rel_path)

                for line_num, line in enumerate(content.splitlines(), 1):
                    for pat_name, stype, regex, base_conf, min_ent in compiled:
                        for match in regex.finditer(line):
                            matched_text = match.group(0)
                            secret_value = _extract_secret_value(match)

                            # ── False positive filtering ──────────
                            if is_false_positive(secret_value):
                                continue

                            # ── Entropy check ─────────────────────
                            if min_ent > 0:
                                ent = shannon_entropy(secret_value)
                                if ent < min_ent:
                                    continue  # Too low entropy — likely a placeholder

                            # ── Compute final confidence ──────────
                            confidence = base_conf * file_confidence_mult

                            # Boost if in a .env-style file
                            if file_path.name in HIGH_CONFIDENCE_FILES:
                                confidence = min(1.0, confidence + 0.1)

                            preview = matched_text[:10] + "..." + matched_text[-4:] if len(matched_text) > 20 else matched_text[:20]
                            context_line = line.strip()[:200]

                            hits.append(
                                ScannerHit(
                                    rule_id=f"secrets/{stype}",
                                    severity="high" if confidence > 0.8 else ("medium" if confidence > 0.5 else "low"),
                                    message=f"{pat_name} detected",
                                    file_path=rel_path,
                                    start_line=line_num,
                                    snippet=context_line,
                                    metadata={
                                        "type": stype,
                                        "confidence": round(confidence, 2),
                                        "value_preview": preview,
                                        "entropy": round(shannon_entropy(secret_value), 2),
                                    },
                                )
                            )
            except PermissionError:
                logger.debug("Secrets scanner: permission denied on %s", file_path)
                continue
            except UnicodeDecodeError:
                logger.debug("Secrets scanner: encoding error on %s", file_path)
                continue
            except Exception as e:
                logger.debug("Secrets scanner: error reading %s: %s", file_path, e)
                continue

        duration = int((time.monotonic() - start) * 1000)
        return ScannerOutput(
            scanner_name=self.name,
            success=True,
            hits=hits,
            duration_ms=duration,
        )

    async def run_targeted(
        self,
        target_path: Path,
        files: list[str],
        rules: list[str],
    ) -> ScannerOutput:
        return await self.run(target_path, file_filter=files)

    def _file_confidence_multiplier(self, rel_path: str) -> float:
        """Adjust confidence based on file path — test files get reduced, config files get boosted."""
        lower = rel_path.lower()

        # High-confidence file types
        for name in HIGH_CONFIDENCE_FILES:
            if lower.endswith(name):
                return 1.1

        # Low-confidence contexts
        for marker in LOW_CONFIDENCE_FILES:
            if marker in lower:
                return 0.5

        return 1.0

    def _collect_files(self, root: Path) -> list[Path]:
        files = []
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            try:
                if path.stat().st_size > 1_000_000:
                    continue
            except OSError:
                continue
            files.append(path)
        return files
