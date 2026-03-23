"""Deterministic file scoring — prioritise files for AI inspection."""

import re
from pathlib import PurePosixPath

# Path patterns and their base scores
PATH_SCORES: list[tuple[str, float]] = [
    # High priority — likely security-relevant
    (r"(auth|login|session|oauth|jwt|token)", 30),
    (r"(password|credential|secret|key)", 25),
    (r"(admin|superuser|privilege)", 20),
    (r"(upload|download|file.*serv)", 20),
    (r"(exec|spawn|system|shell|command)", 25),
    (r"(sql|query|database|db|dao|repository)", 15),
    (r"(crypto|encrypt|decrypt|hash|sign)", 15),
    (r"(deseriali[sz]|marshal|unpickle|yaml\.load|json\.parse)", 25),
    (r"(route|controller|handler|endpoint|view|api)", 15),
    (r"(middleware|interceptor|filter|guard)", 12),
    (r"(template|render|inject|sanitiz)", 12),
    (r"(config|settings|env)", 10),
    (r"(webhook|callback|notify)", 10),
    (r"(payment|billing|checkout|stripe|paypal)", 20),
    (r"(user|account|profile|register)", 10),
    # Android — high priority components and security surfaces
    (r"AndroidManifest\.xml", 35),
    (r"(Activity|Fragment|Service|BroadcastReceiver|ContentProvider)", 15),
    (r"(WebView|JavascriptInterface|addJavascriptInterface)", 30),
    (r"(SharedPreferences|getSharedPreferences)", 15),
    (r"(SQLiteDatabase|ContentResolver|rawQuery)", 20),
    (r"(Intent|startActivity|sendBroadcast|bindService)", 12),
    (r"(Permission|checkSelfPermission|requestPermissions)", 10),
    (r"(KeyStore|TrustManager|SSLSocket|HttpsURLConnection)", 20),
    (r"(PackageManager|getInstalledPackages)", 10),
    (r"google.services\.json", 20),
    # Medium priority
    (r"(model|schema|entity|migration)", 8),
    (r"(service|manager|provider)", 8),
    (r"(util|helper|common|shared)", 5),
    # Lower priority
    (r"(test|spec|mock|fixture|__test__)", -15),
    (r"(doc|readme|changelog|license|contributing)", -20),
    (r"(\.min\.|\.bundle\.|vendor|third.?party)", -25),
    (r"(\.d\.ts$|\.map$|\.lock$)", -20),
    (r"(generated|auto.?gen|\.g\.)", -15),
]

# File extensions and their relevance multipliers
EXTENSION_MULTIPLIERS: dict[str, float] = {
    ".py": 1.0,
    ".js": 1.0,
    ".ts": 1.0,
    ".jsx": 0.9,
    ".tsx": 0.9,
    ".java": 1.0,
    ".go": 1.0,
    ".rs": 1.0,
    ".rb": 1.0,
    ".php": 1.0,
    ".cs": 1.0,
    ".kt": 1.0,
    ".scala": 0.9,
    ".swift": 0.9,
    ".c": 0.8,
    ".cpp": 0.8,
    ".h": 0.6,
    ".sql": 0.7,
    ".html": 0.4,
    ".vue": 0.8,
    ".svelte": 0.8,
    ".yaml": 0.5,
    ".yml": 0.5,
    ".json": 0.3,
    ".toml": 0.4,
    ".ini": 0.4,
    ".env": 0.6,
    ".xml": 0.4,
    ".sh": 0.5,
    ".bash": 0.5,
    ".dockerfile": 0.5,
    ".tf": 0.5,
}


def score_file(
    file_path: str,
    *,
    language: str | None = None,
    line_count: int = 0,
    scanner_hit_count: int = 0,
    has_dependency_risk: bool = False,
    has_secret_candidate: bool = False,
) -> tuple[float, dict[str, float]]:
    """
    Score a file's priority for AI inspection.

    Returns (total_score, reasons_dict).
    """
    reasons: dict[str, float] = {}
    p = PurePosixPath(file_path)

    # Extension multiplier
    ext = p.suffix.lower()
    ext_mult = EXTENSION_MULTIPLIERS.get(ext, 0.2)
    reasons["extension"] = ext_mult

    # Path pattern matching — track best positive and worst negative separately
    # (prevents triple-boost for auth_api_handler.py matching auth+api+handler)
    path_lower = file_path.lower()
    best_positive = 0.0
    worst_negative = 0.0
    for pattern, score in PATH_SCORES:
        if re.search(pattern, path_lower):
            if score > 0 and score > best_positive:
                best_positive = score
            elif score < 0 and score < worst_negative:
                worst_negative = score
    path_score = best_positive + worst_negative  # negative scores penalise
    if path_score != 0:
        reasons["path_match"] = path_score

    # File size relevance (very small or very large = less useful)
    size_score = 0.0
    if 10 < line_count < 500:
        size_score = 5.0
    elif 500 <= line_count < 2000:
        size_score = 3.0
    elif line_count >= 2000:
        size_score = 1.0
    reasons["size"] = size_score

    # Scanner hits boost
    scanner_score = min(scanner_hit_count * 5.0, 30.0)
    if scanner_score > 0:
        reasons["scanner_hits"] = scanner_score

    # Dependency risk boost
    if has_dependency_risk:
        reasons["dep_risk"] = 10.0

    # Secret candidate boost
    if has_secret_candidate:
        reasons["secret_candidate"] = 15.0

    total = (path_score + size_score + scanner_score +
             reasons.get("dep_risk", 0) + reasons.get("secret_candidate", 0)) * ext_mult

    return total, reasons
