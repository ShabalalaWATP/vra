"""Structural code analysis — extract symbols, imports, and metadata."""

import re
import textwrap
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractedSymbol:
    name: str
    kind: str  # function, class, method, variable, route
    start_line: int
    end_line: int | None = None
    signature: str | None = None
    tags: dict = field(default_factory=dict)


@dataclass
class FileStructure:
    imports: list[str] = field(default_factory=list)
    symbols: list[ExtractedSymbol] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    framework_hints: list[str] = field(default_factory=list)
    call_sites: list[dict] = field(default_factory=list)


# Python patterns
PY_FUNC_RE = re.compile(r"^([ \t]*)def\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE)
PY_CLASS_RE = re.compile(r"^([ \t]*)class\s+(\w+)\s*[:(]", re.MULTILINE)
PY_IMPORT_RE = re.compile(r"^(?:from\s+(\S+)\s+)?import\s+(.+)", re.MULTILINE)
PY_ROUTE_RE = re.compile(
    r"@\w*\.(?:route|get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", re.MULTILINE
)

# JavaScript/TypeScript patterns
JS_FUNC_RE = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE
)
JS_CLASS_RE = re.compile(r"(?:export\s+)?class\s+(\w+)", re.MULTILINE)
JS_ARROW_RE = re.compile(
    r"(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>", re.MULTILINE
)
JS_IMPORT_RE = re.compile(
    r"(?:import\s+.*?from\s+['\"]([^'\"]+)['\"]|require\s*\(\s*['\"]([^'\"]+)['\"]\s*\))",
    re.MULTILINE,
)
JS_ROUTE_RE = re.compile(
    r"(?:app|router|server)\.\s*(?:get|post|put|delete|patch|use)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

# Java patterns
JAVA_CLASS_RE = re.compile(r"(?:public\s+)?class\s+(\w+)", re.MULTILINE)
JAVA_METHOD_RE = re.compile(
    r"(?:public|private|protected)?\s*(?:static\s+)?(?:\w+)\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE
)
JAVA_IMPORT_RE = re.compile(r"^import\s+([^;]+);", re.MULTILINE)
JAVA_ROUTE_RE = re.compile(
    r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

# PHP patterns
PHP_FUNC_RE = re.compile(
    r"(?:public|private|protected)?\s*(?:static\s+)?function\s+(\w+)\s*\(([^)]*)\)", re.MULTILINE
)
PHP_CLASS_RE = re.compile(r"(?:abstract\s+)?class\s+(\w+)(?:\s+extends\s+\w+)?(?:\s+implements\s+[\w,\s]+)?", re.MULTILINE)
PHP_USE_RE = re.compile(r"^use\s+([^;]+);", re.MULTILINE)
PHP_INCLUDE_RE = re.compile(r"(?:include|require)(?:_once)?\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", re.MULTILINE)
PHP_CALL_RE = re.compile(r"(\$?\w+(?:::|->)\w+)\s*\(", re.MULTILINE)
PHP_ROUTE_RE = re.compile(
    r"(?:\$app|\$router|Route)(?:::|\->)\s*(?:get|post|put|delete|patch|map)\s*\(\s*['\"]([^'\"]+)['\"]",
    re.MULTILINE,
)

# Security-relevant tags
SECURITY_PATTERNS = {
    "auth": re.compile(r"(?i)(authenticate|authorize|login|logout|session|jwt|oauth|rbac)"),
    "crypto": re.compile(r"(?i)(encrypt|decrypt|hash|sign|verify|hmac|aes|rsa|sha)"),
    "db_access": re.compile(r"(?i)(query|execute|cursor|select|insert|update|delete|orm|model)"),
    "file_io": re.compile(r"(?i)(open|read|write|upload|download|file|stream|path)"),
    "command_exec": re.compile(r"(?i)(exec|spawn|system|popen|subprocess|shell|cmd)"),
    "deserialization": re.compile(r"(?i)(deseriali[sz]e|unmarshal|unpickle|loads|parse|fromjson)"),
    "network": re.compile(r"(?i)(http|request|fetch|socket|connect|url|endpoint)"),
    "template": re.compile(r"(?i)(render|template|jinja|mustache|ejs|handlebars)"),
    "input_handling": re.compile(r"(?i)(request\.|req\.|params|body|query|form|input|args)"),
}


def extract_structure(content: str, language: str) -> FileStructure:
    """Extract symbols, imports, and routes from file content."""
    content = textwrap.dedent(content)
    structure = FileStructure()
    content_lines = content.splitlines()

    if language in ("python",):
        _extract_python(content, structure)
    elif language in ("javascript", "typescript"):
        _extract_javascript(content, structure)
    elif language in ("java", "kotlin"):
        _extract_java(content, structure)
    elif language in ("php",):
        _extract_php(content, structure)
    else:
        # Generic: try all patterns
        _extract_python(content, structure)
        _extract_javascript(content, structure)

    # Tag symbols with security-relevant markers
    for sym in structure.symbols:
        context_end = sym.end_line or sym.start_line
        body_text = "\n".join(content_lines[max(0, sym.start_line - 1):context_end])
        sig = (sym.name + " " + (sym.signature or "") + " " + body_text).lower()
        for tag_name, pattern in SECURITY_PATTERNS.items():
            if pattern.search(sig):
                sym.tags[tag_name] = True

    return structure


def _extract_python(content: str, structure: FileStructure):
    lines = content.splitlines()

    for m in PY_IMPORT_RE.finditer(content):
        module = m.group(1) or m.group(2)
        structure.imports.append(module.strip())

    for m in PY_CLASS_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        indent = len(m.group(1))
        structure.symbols.append(
            ExtractedSymbol(
                name=m.group(2), kind="class",
                start_line=line_num,
                end_line=_find_python_block_end(lines, line_num, indent),
                signature=m.group(0).strip(),
            )
        )

    for m in PY_FUNC_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        indent = len(m.group(1))
        kind = "method" if indent > 0 else "function"
        structure.symbols.append(
            ExtractedSymbol(
                name=m.group(2), kind=kind,
                start_line=line_num,
                end_line=_find_python_block_end(lines, line_num, indent),
                signature=m.group(0).strip(),
            )
        )

    for m in PY_ROUTE_RE.finditer(content):
        structure.routes.append({"path": m.group(1), "line": content[:m.start()].count("\n") + 1})


def _find_python_block_end(lines: list[str], start_line: int, indent: int) -> int:
    """Find the last line in a Python indented block."""
    end_line = start_line
    for idx in range(start_line, len(lines)):
        raw_line = lines[idx]
        stripped = raw_line.strip()
        if not stripped:
            continue

        current_indent = len(raw_line) - len(raw_line.lstrip(" \t"))
        if current_indent <= indent and not stripped.startswith("#"):
            break
        end_line = idx + 1

    return end_line


def _extract_javascript(content: str, structure: FileStructure):
    for m in JS_IMPORT_RE.finditer(content):
        module = m.group(1) or m.group(2)
        if module:
            structure.imports.append(module)

    for m in JS_CLASS_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        structure.symbols.append(
            ExtractedSymbol(name=m.group(1), kind="class", start_line=line_num)
        )

    for m in JS_FUNC_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        structure.symbols.append(
            ExtractedSymbol(
                name=m.group(1), kind="function",
                start_line=line_num, signature=m.group(0).strip(),
            )
        )

    for m in JS_ARROW_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        structure.symbols.append(
            ExtractedSymbol(name=m.group(1), kind="function", start_line=line_num)
        )

    for m in JS_ROUTE_RE.finditer(content):
        structure.routes.append({"path": m.group(1), "line": content[:m.start()].count("\n") + 1})


def _extract_java(content: str, structure: FileStructure):
    for m in JAVA_IMPORT_RE.finditer(content):
        structure.imports.append(m.group(1).strip())

    for m in JAVA_CLASS_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        structure.symbols.append(
            ExtractedSymbol(name=m.group(1), kind="class", start_line=line_num)
        )

    for m in JAVA_METHOD_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        structure.symbols.append(
            ExtractedSymbol(
                name=m.group(1), kind="method",
                start_line=line_num, signature=m.group(0).strip(),
            )
        )

    for m in JAVA_ROUTE_RE.finditer(content):
        structure.routes.append({"path": m.group(1), "line": content[:m.start()].count("\n") + 1})


def _extract_php(content: str, structure: FileStructure):
    """Extract PHP functions, classes, imports, and routes."""
    # Imports: use statements and include/require
    for m in PHP_USE_RE.finditer(content):
        structure.imports.append(m.group(1).strip())
    for m in PHP_INCLUDE_RE.finditer(content):
        structure.imports.append(m.group(1).strip())

    # Classes
    for m in PHP_CLASS_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        structure.symbols.append(
            ExtractedSymbol(name=m.group(1), kind="class", start_line=line_num)
        )

    # Functions and methods
    for m in PHP_FUNC_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        structure.symbols.append(
            ExtractedSymbol(
                name=m.group(1), kind="function",
                start_line=line_num, signature=m.group(0).strip(),
            )
        )

    # Call sites (for call graph edges)
    for m in PHP_CALL_RE.finditer(content):
        line_num = content[:m.start()].count("\n") + 1
        call_expr = m.group(1)
        # Split Class::method or $obj->method
        if "::" in call_expr:
            parts = call_expr.split("::")
            structure.call_sites.append({
                "name": parts[-1], "object": parts[0].lstrip("$"),
                "line": line_num,
            })
        elif "->" in call_expr:
            parts = call_expr.split("->")
            structure.call_sites.append({
                "name": parts[-1], "object": parts[0].lstrip("$"),
                "line": line_num,
            })

    # Routes
    for m in PHP_ROUTE_RE.finditer(content):
        structure.routes.append({"path": m.group(1), "line": content[:m.start()].count("\n") + 1})
