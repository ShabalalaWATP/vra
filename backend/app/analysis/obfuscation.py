"""Obfuscation and minification detection.

Analyses source files to detect:
- Minified JavaScript/CSS (no whitespace, very long lines)
- Obfuscated code (single-char variables, hex-encoded strings, eval packing)
- Packed code (base64-encoded payloads, packer wrappers)
- Source maps (indicating a build artifact)
- Vendor/third-party bundled code

Each file gets an obfuscation score (0.0 = clearly human-written, 1.0 = fully obfuscated)
and a classification label. This feeds into:
- File scoring (obfuscated files get deprioritised for AI inspection)
- Architecture understanding (AI is told which files are obfuscated)
- Report limitations (methodology section notes obfuscated coverage)
"""

import math
import re
from collections import Counter
from dataclasses import dataclass


@dataclass
class ObfuscationResult:
    """Assessment of a file's obfuscation level."""

    score: float  # 0.0 = clean, 1.0 = fully obfuscated
    label: str  # clean, minified, obfuscated, packed, vendor_bundle, source_map
    reasons: list[str]  # Why this classification was given
    is_analysable: bool  # Whether the AI should attempt deep analysis
    avg_line_length: float = 0.0
    max_line_length: int = 0
    unique_var_ratio: float = 0.0  # Ratio of single-char identifiers

    @property
    def severity(self) -> str:
        if self.score >= 0.8:
            return "heavy"
        if self.score >= 0.5:
            return "moderate"
        if self.score >= 0.2:
            return "light"
        return "none"


# ── Patterns for detection ───────────────────────────────────────

# JavaScript packer patterns
PACKER_PATTERNS = [
    re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*[dr]\s*\)"),  # Dean Edwards packer
    re.compile(r"eval\s*\(\s*atob\s*\("),  # Base64 eval
    re.compile(r"eval\s*\(\s*unescape\s*\("),  # Unescape eval
    re.compile(r"eval\s*\(\s*String\.fromCharCode\s*\("),  # CharCode eval
    re.compile(r"\$=~\[\];"),  # JSFuck
    re.compile(r"_0x[0-9a-f]{4,}"),  # Hex-encoded variable names (common obfuscator output)
]

# Hex-encoded string patterns
HEX_STRING_PATTERN = re.compile(r"\\x[0-9a-fA-F]{2}")
UNICODE_ESCAPE_PATTERN = re.compile(r"\\u[0-9a-fA-F]{4}")

# Source map reference
SOURCE_MAP_PATTERN = re.compile(r"//[#@]\s*sourceMappingURL\s*=")

# Common single-char variable names in obfuscated code
SINGLE_CHAR_VAR = re.compile(r"\b[a-zA-Z]\b")

# Base64-encoded payload (long base64 string)
BASE64_PAYLOAD = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")

# Minified patterns — very long lines with lots of semicolons/braces
DENSE_CODE_PATTERN = re.compile(r"[;{}()]{3,}")


def detect_obfuscation(
    content: str,
    file_path: str,
    language: str | None = None,
) -> ObfuscationResult:
    """
    Analyse a file's content to detect obfuscation, minification, or packing.

    Returns an ObfuscationResult with score, label, and reasons.
    """
    reasons: list[str] = []
    score = 0.0

    if not content or not content.strip():
        return ObfuscationResult(
            score=0.0, label="empty", reasons=["File is empty"],
            is_analysable=False,
        )

    lines = content.splitlines()
    if not lines:
        return ObfuscationResult(
            score=0.0, label="empty", reasons=["No lines"],
            is_analysable=False,
        )

    # ── Source map check ──────────────────────────────────────────
    if file_path.endswith(".map") or file_path.endswith(".js.map"):
        return ObfuscationResult(
            score=1.0, label="source_map", reasons=["Source map file"],
            is_analysable=False,
        )

    # ── Filename heuristics ───────────────────────────────────────
    lower_path = file_path.lower()
    if ".min." in lower_path:
        score += 0.6
        reasons.append("Filename contains .min.")
    if ".bundle." in lower_path or ".bundled." in lower_path:
        score += 0.3
        reasons.append("Filename indicates bundle")
    if "vendor/" in lower_path or "third_party/" in lower_path or "third-party/" in lower_path:
        score += 0.2
        reasons.append("File is in vendor/third-party directory")
    if "/dist/" in lower_path or "/build/" in lower_path:
        score += 0.15
        reasons.append("File is in dist/build output directory")

    # ── Line length analysis ──────────────────────────────────────
    line_lengths = [len(line) for line in lines]
    avg_line_length = sum(line_lengths) / len(line_lengths) if line_lengths else 0
    max_line_length = max(line_lengths) if line_lengths else 0
    total_chars = sum(line_lengths)

    # Minified code has very few lines but very long ones
    if max_line_length > 5000:
        score += 0.5
        reasons.append(f"Extremely long line: {max_line_length} chars")
    elif max_line_length > 1000 and len(lines) < 20:
        score += 0.4
        reasons.append(f"Long lines ({max_line_length} chars) with few lines ({len(lines)})")
    elif avg_line_length > 200:
        score += 0.3
        reasons.append(f"High average line length: {avg_line_length:.0f} chars")

    # ── Whitespace ratio ──────────────────────────────────────────
    if total_chars > 0:
        whitespace_chars = sum(1 for c in content if c in (' ', '\t', '\n'))
        whitespace_ratio = whitespace_chars / total_chars

        if whitespace_ratio < 0.05 and total_chars > 500:
            score += 0.4
            reasons.append(f"Very low whitespace ratio: {whitespace_ratio:.1%}")
        elif whitespace_ratio < 0.10 and total_chars > 1000:
            score += 0.2
            reasons.append(f"Low whitespace ratio: {whitespace_ratio:.1%}")

    # ── Packer/eval detection ─────────────────────────────────────
    for pattern in PACKER_PATTERNS:
        if pattern.search(content):
            score += 0.5
            reasons.append(f"Packer/eval pattern detected: {pattern.pattern[:50]}")
            break  # One match is enough

    # ── Hex/unicode encoded strings ───────────────────────────────
    hex_count = len(HEX_STRING_PATTERN.findall(content))
    unicode_count = len(UNICODE_ESCAPE_PATTERN.findall(content))

    if hex_count > 20:
        score += 0.3
        reasons.append(f"High hex-encoded string density: {hex_count} occurrences")
    elif hex_count > 5:
        score += 0.1
        reasons.append(f"Hex-encoded strings present: {hex_count}")

    if unicode_count > 50:
        score += 0.2
        reasons.append(f"High unicode escape density: {unicode_count}")

    # ── Hex variable names (_0x pattern) ──────────────────────────
    hex_vars = re.findall(r"_0x[0-9a-f]{4,}", content)
    if len(hex_vars) > 5:
        score += 0.5
        reasons.append(f"Obfuscator-style hex variable names: {len(hex_vars)} found")
    elif len(hex_vars) > 0:
        score += 0.2
        reasons.append(f"Some hex variable names: {len(hex_vars)}")

    # ── Single-character identifier ratio ─────────────────────────
    # Also applies to Java/Kotlin (ProGuard/R8 obfuscation in decompiled APKs)
    if language in ("javascript", "typescript", "java", "kotlin") and total_chars > 500:
        # Count identifiers — rough heuristic
        words = re.findall(r"\b[a-zA-Z_$][a-zA-Z0-9_$]*\b", content)
        if words:
            single_char = sum(1 for w in words if len(w) == 1)
            ratio = single_char / len(words)
            if ratio > 0.3 and len(words) > 50:
                score += 0.3
                reasons.append(f"High single-char identifier ratio: {ratio:.0%}")
            elif ratio > 0.2 and len(words) > 100:
                score += 0.15
                reasons.append(f"Elevated single-char identifiers: {ratio:.0%}")

    # ── jadx decompilation artifacts (Android APK) ────────────────
    if language in ("java", "kotlin"):
        jadx_markers = 0
        # JADX warning comments
        if "/* JADX" in content or "// JADX" in content:
            jadx_markers += content.count("JADX")
        # goto statements (jadx artifact for unresolvable control flow)
        goto_count = len(re.findall(r"\bgoto\b", content))
        if goto_count > 3:
            jadx_markers += goto_count
        # ProGuard/R8 obfuscated class names (a.b.c.d pattern)
        proguard_imports = len(re.findall(r"import\s+[a-z](\.[a-z]){2,};", content))
        if proguard_imports > 3:
            score += 0.3
            reasons.append(f"ProGuard/R8 obfuscated imports: {proguard_imports}")
        # Single-letter class names in declarations
        short_classes = len(re.findall(r"\bclass\s+[a-z]\b", content))
        if short_classes > 0:
            score += 0.2
            reasons.append(f"Obfuscated single-letter class names: {short_classes}")
        if jadx_markers > 5:
            score += 0.15
            reasons.append(f"jadx decompilation artifacts: {jadx_markers} markers")

    # ── Base64 payload detection ──────────────────────────────────
    b64_matches = BASE64_PAYLOAD.findall(content)
    if b64_matches:
        longest_b64 = max(len(m) for m in b64_matches)
        if longest_b64 > 500:
            score += 0.3
            reasons.append(f"Large base64 payload: {longest_b64} chars")
        elif longest_b64 > 100:
            score += 0.1
            reasons.append(f"Base64 content present: {longest_b64} chars")

    # ── Source map reference in code ───────────────────────────────
    if SOURCE_MAP_PATTERN.search(content):
        score += 0.1
        reasons.append("Contains sourceMappingURL (build artifact)")

    # ── Dense code pattern (many consecutive operators) ───────────
    dense_matches = DENSE_CODE_PATTERN.findall(content)
    if len(dense_matches) > 20 and avg_line_length > 100:
        score += 0.15
        reasons.append("Dense consecutive operators/braces")

    # ── Clamp score ───────────────────────────────────────────────
    score = min(1.0, max(0.0, score))

    # ── Determine label ───────────────────────────────────────────
    if score >= 0.7 and any("packer" in r.lower() or "eval" in r.lower() or "hex variable" in r.lower() for r in reasons):
        label = "obfuscated"
    elif score >= 0.5 and any("bundle" in r.lower() or "vendor" in r.lower() for r in reasons):
        label = "vendor_bundle"
    elif score >= 0.4:
        label = "minified"
    elif score >= 0.15:
        label = "possibly_minified"
    else:
        label = "clean"

    # ── Determine analysability ───────────────────────────────────
    # Files with score > 0.7 are not worth deep AI inspection
    # Files with 0.4-0.7 should be flagged but can still be scanned
    is_analysable = score < 0.7

    return ObfuscationResult(
        score=score,
        label=label,
        reasons=reasons,
        is_analysable=is_analysable,
        avg_line_length=avg_line_length,
        max_line_length=max_line_length,
    )


def summarise_obfuscation(results: dict[str, ObfuscationResult]) -> dict:
    """
    Summarise obfuscation detection across all files in a scan.
    Returns a dict suitable for inclusion in the report.
    """
    total = len(results)
    if total == 0:
        return {"total_files": 0, "obfuscated_count": 0}

    by_label = Counter(r.label for r in results.values())
    non_analysable = [path for path, r in results.items() if not r.is_analysable]
    heavily_obfuscated = [path for path, r in results.items() if r.score >= 0.7]
    moderately_obfuscated = [path for path, r in results.items() if 0.4 <= r.score < 0.7]

    obfuscated_pct = (len(heavily_obfuscated) + len(moderately_obfuscated)) / total * 100

    return {
        "total_files": total,
        "obfuscated_count": len(heavily_obfuscated) + len(moderately_obfuscated),
        "obfuscated_percentage": round(obfuscated_pct, 1),
        "heavily_obfuscated": len(heavily_obfuscated),
        "moderately_obfuscated": len(moderately_obfuscated),
        "non_analysable_count": len(non_analysable),
        "by_label": dict(by_label),
        "heavily_obfuscated_files": heavily_obfuscated[:20],
        "moderately_obfuscated_files": moderately_obfuscated[:20],
    }
