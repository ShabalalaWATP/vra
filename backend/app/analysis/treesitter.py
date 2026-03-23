"""Tree-sitter based structural analysis — proper AST parsing for symbol extraction."""

import logging
import textwrap
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Try to import tree-sitter; fall back to regex-based extraction if unavailable
_TS_AVAILABLE = False
try:
    import tree_sitter_languages
    _TS_AVAILABLE = True
except ImportError:
    logger.warning("tree-sitter-languages not installed; falling back to regex parsing")

# Language mapping
TREESITTER_LANG_MAP = {
    "python": "python",
    "javascript": "javascript",
    "typescript": "typescript",
    "java": "java",
    "go": "go",
    "rust": "rust",
    "ruby": "ruby",
    "php": "php",
    "csharp": "c_sharp",
    "c": "c",
    "cpp": "cpp",
    "kotlin": "kotlin",
    "scala": "scala",
    "swift": "swift",
}


@dataclass
class TSSymbol:
    name: str
    kind: str  # function, class, method, variable, interface, struct
    start_line: int
    end_line: int
    start_col: int = 0
    end_col: int = 0
    signature: str | None = None
    parent: str | None = None  # Enclosing class/struct name
    tags: dict = field(default_factory=dict)
    body_text: str | None = None  # The raw text of the symbol body


@dataclass
class TSImport:
    module: str
    alias: str | None = None
    imported_names: list[str] = field(default_factory=list)  # e.g., ["User", "Admin"] from "from models import User, Admin"
    line: int = 0


@dataclass
class TSCallSite:
    """A function/method call expression found in the source code."""

    callee_name: str  # The function/method being called
    callee_object: str | None = None  # The receiver, e.g., "db" in db.execute()
    line: int = 0
    enclosing_symbol: str | None = None  # Which function/method contains this call
    argument_count: int = 0
    is_method_call: bool = False  # True if obj.method(), False if function()
    full_expression: str = ""  # e.g., "db.execute" or "os.system"


@dataclass
class TSFileAnalysis:
    language: str
    symbols: list[TSSymbol] = field(default_factory=list)
    imports: list[TSImport] = field(default_factory=list)
    call_sites: list[TSCallSite] = field(default_factory=list)
    routes: list[dict] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    line_count: int = 0
    has_main: bool = False


def is_available() -> bool:
    return _TS_AVAILABLE


def parse_file(content: str, language: str) -> TSFileAnalysis:
    """Parse a file using Tree-sitter and extract structural information."""
    content = textwrap.dedent(content)
    ts_lang = TREESITTER_LANG_MAP.get(language)
    if not ts_lang or not _TS_AVAILABLE:
        # Fall back to regex
        from app.analysis.structure import extract_structure
        fallback = extract_structure(content, language)
        return TSFileAnalysis(
            language=language,
            symbols=[
                TSSymbol(
                    name=s.name, kind=s.kind,
                    start_line=s.start_line, end_line=s.end_line or s.start_line,
                    signature=s.signature, tags=s.tags,
                )
                for s in fallback.symbols
            ],
            imports=[TSImport(module=imp) for imp in fallback.imports],
            routes=[r for r in fallback.routes],
            line_count=len(content.splitlines()),
        )

    parser = tree_sitter_languages.get_parser(ts_lang)
    tree = parser.parse(content.encode("utf-8"))
    root = tree.root_node

    analysis = TSFileAnalysis(
        language=language,
        line_count=len(content.splitlines()),
    )

    lines = content.encode("utf-8")

    if language == "python":
        _extract_python_ts(root, lines, analysis)
    elif language in ("javascript", "typescript"):
        _extract_js_ts(root, lines, analysis)
    elif language == "java":
        _extract_java_ts(root, lines, analysis)
    elif language == "go":
        _extract_go_ts(root, lines, analysis)
    elif language == "rust":
        _extract_rust_ts(root, lines, analysis)
    else:
        _extract_generic_ts(root, lines, analysis)

    # Extract call sites (works across all languages via common AST patterns)
    _extract_call_sites(root, lines, analysis)

    return analysis


def _node_text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _extract_python_ts(root, source: bytes, analysis: TSFileAnalysis):
    """Extract symbols from Python using Tree-sitter."""
    for node in _walk(root):
        ntype = node.type

        # Imports
        if ntype == "import_statement":
            text = _node_text(node, source)
            module = text.replace("import ", "").strip()
            analysis.imports.append(TSImport(module=module, line=node.start_point[0] + 1))

        elif ntype == "import_from_statement":
            module_node = node.child_by_field_name("module_name")
            if module_node:
                analysis.imports.append(TSImport(
                    module=_node_text(module_node, source),
                    line=node.start_point[0] + 1,
                ))

        # Functions
        elif ntype == "function_definition":
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            if name_node:
                name = _node_text(name_node, source)
                params = _node_text(params_node, source) if params_node else "()"
                # Determine if method (inside class)
                parent_class = _find_parent_class(node)
                kind = "method" if parent_class else "function"
                sym = TSSymbol(
                    name=name,
                    kind=kind,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    signature=f"def {name}{params}",
                    parent=parent_class,
                )
                _tag_security_relevance(sym, _node_text(node, source))
                analysis.symbols.append(sym)

                # Check for route decorators
                _check_python_decorators(node, source, analysis)

                if name == "main" or name == "__main__":
                    analysis.has_main = True

        # Classes
        elif ntype == "class_definition":
            name_node = node.child_by_field_name("name")
            if name_node:
                name = _node_text(name_node, source)
                analysis.symbols.append(TSSymbol(
                    name=name,
                    kind="class",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    signature=_node_text(node, source).split(":")[0].strip(),
                ))

        # Comments
        elif ntype == "comment":
            text = _node_text(node, source).strip()
            if any(kw in text.lower() for kw in ("todo", "fixme", "hack", "security", "vuln", "unsafe", "danger")):
                analysis.comments.append(text)


def _check_python_decorators(func_node, source: bytes, analysis: TSFileAnalysis):
    """Check if a Python function has route decorators."""
    import re
    # Look at the preceding siblings for decorators
    parent = func_node.parent
    if not parent:
        return
    idx = None
    for i, child in enumerate(parent.children):
        if child.id == func_node.id:
            idx = i
            break
    if idx is None:
        return

    for i in range(max(0, idx - 5), idx):
        sibling = parent.children[i]
        if sibling.type == "decorator":
            text = _node_text(sibling, source)
            route_match = re.search(
                r"@\w*\.(?:route|get|post|put|delete|patch)\s*\(['\"]([^'\"]+)['\"]",
                text,
            )
            if route_match:
                method = "GET"
                if ".post" in text:
                    method = "POST"
                elif ".put" in text:
                    method = "PUT"
                elif ".delete" in text:
                    method = "DELETE"
                elif ".patch" in text:
                    method = "PATCH"
                analysis.routes.append({
                    "path": route_match.group(1),
                    "method": method,
                    "line": sibling.start_point[0] + 1,
                })


def _extract_js_ts(root, source: bytes, analysis: TSFileAnalysis):
    """Extract symbols from JavaScript/TypeScript."""
    for node in _walk(root):
        ntype = node.type

        # Imports
        if ntype == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node:
                module = _node_text(source_node, source).strip("'\"")
                analysis.imports.append(TSImport(module=module, line=node.start_point[0] + 1))

        # Functions
        elif ntype in ("function_declaration", "method_definition"):
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            if name_node:
                name = _node_text(name_node, source)
                params = _node_text(params_node, source) if params_node else "()"
                kind = "method" if ntype == "method_definition" else "function"
                parent_class = _find_parent_class_js(node)
                sym = TSSymbol(
                    name=name,
                    kind=kind,
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    signature=f"function {name}{params}",
                    parent=parent_class,
                )
                _tag_security_relevance(sym, _node_text(node, source))
                analysis.symbols.append(sym)

        # Arrow functions assigned to variables
        elif ntype == "lexical_declaration" or ntype == "variable_declaration":
            for child in node.children:
                if child.type == "variable_declarator":
                    name_node = child.child_by_field_name("name")
                    value_node = child.child_by_field_name("value")
                    if name_node and value_node and value_node.type == "arrow_function":
                        name = _node_text(name_node, source)
                        sym = TSSymbol(
                            name=name,
                            kind="function",
                            start_line=node.start_point[0] + 1,
                            end_line=node.end_point[0] + 1,
                            signature=f"const {name} = (...) =>",
                        )
                        _tag_security_relevance(sym, _node_text(node, source))
                        analysis.symbols.append(sym)

        # Classes
        elif ntype == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                analysis.symbols.append(TSSymbol(
                    name=_node_text(name_node, source),
                    kind="class",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                ))

        # Express-style routes
        elif ntype == "call_expression":
            text = _node_text(node, source)
            import re
            route_match = re.search(
                r"(?:app|router|server)\.\s*(get|post|put|delete|patch|use)\s*\(\s*['\"]([^'\"]+)['\"]",
                text,
            )
            if route_match:
                analysis.routes.append({
                    "method": route_match.group(1).upper(),
                    "path": route_match.group(2),
                    "line": node.start_point[0] + 1,
                })

        # Comments
        elif ntype == "comment":
            text = _node_text(node, source).strip()
            if any(kw in text.lower() for kw in ("todo", "fixme", "hack", "security", "vuln", "unsafe")):
                analysis.comments.append(text)


def _extract_java_ts(root, source: bytes, analysis: TSFileAnalysis):
    """Extract symbols from Java."""
    for node in _walk(root):
        ntype = node.type

        if ntype == "import_declaration":
            text = _node_text(node, source)
            module = text.replace("import ", "").rstrip(";").strip()
            analysis.imports.append(TSImport(module=module, line=node.start_point[0] + 1))

        elif ntype == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                analysis.symbols.append(TSSymbol(
                    name=_node_text(name_node, source),
                    kind="class",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                ))

        elif ntype == "method_declaration":
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            if name_node:
                name = _node_text(name_node, source)
                params = _node_text(params_node, source) if params_node else "()"
                parent_class = _find_parent_class(node)
                sym = TSSymbol(
                    name=name,
                    kind="method",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    signature=f"{name}{params}",
                    parent=parent_class,
                )
                _tag_security_relevance(sym, _node_text(node, source))
                analysis.symbols.append(sym)

        # Spring annotations for routes
        elif ntype == "annotation":
            text = _node_text(node, source)
            import re
            route_match = re.search(
                r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(?['\"]?([^'\")\s]+)",
                text,
            )
            if route_match:
                analysis.routes.append({
                    "path": route_match.group(1),
                    "line": node.start_point[0] + 1,
                })


def _extract_go_ts(root, source: bytes, analysis: TSFileAnalysis):
    """Extract symbols from Go."""
    for node in _walk(root):
        ntype = node.type

        if ntype == "import_spec":
            path_node = node.child_by_field_name("path")
            if path_node:
                module = _node_text(path_node, source).strip('"')
                analysis.imports.append(TSImport(module=module, line=node.start_point[0] + 1))

        elif ntype == "function_declaration":
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            if name_node:
                name = _node_text(name_node, source)
                params = _node_text(params_node, source) if params_node else "()"
                sym = TSSymbol(
                    name=name,
                    kind="function",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    signature=f"func {name}{params}",
                )
                _tag_security_relevance(sym, _node_text(node, source))
                analysis.symbols.append(sym)

                if name == "main":
                    analysis.has_main = True

        elif ntype == "method_declaration":
            name_node = node.child_by_field_name("name")
            receiver_node = node.child_by_field_name("receiver")
            if name_node:
                name = _node_text(name_node, source)
                receiver = _node_text(receiver_node, source) if receiver_node else ""
                sym = TSSymbol(
                    name=name,
                    kind="method",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    signature=f"func {receiver} {name}",
                )
                _tag_security_relevance(sym, _node_text(node, source))
                analysis.symbols.append(sym)

        elif ntype == "type_declaration":
            for child in node.children:
                if child.type == "type_spec":
                    name_node = child.child_by_field_name("name")
                    type_node = child.child_by_field_name("type")
                    if name_node:
                        kind = "struct" if type_node and type_node.type == "struct_type" else "type"
                        analysis.symbols.append(TSSymbol(
                            name=_node_text(name_node, source),
                            kind=kind,
                            start_line=child.start_point[0] + 1,
                            end_line=child.end_point[0] + 1,
                        ))


def _extract_rust_ts(root, source: bytes, analysis: TSFileAnalysis):
    """Extract symbols from Rust."""
    for node in _walk(root):
        ntype = node.type

        if ntype == "use_declaration":
            text = _node_text(node, source)
            module = text.replace("use ", "").rstrip(";").strip()
            analysis.imports.append(TSImport(module=module, line=node.start_point[0] + 1))

        elif ntype == "function_item":
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            if name_node:
                name = _node_text(name_node, source)
                params = _node_text(params_node, source) if params_node else "()"
                sym = TSSymbol(
                    name=name,
                    kind="function",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                    signature=f"fn {name}{params}",
                )
                _tag_security_relevance(sym, _node_text(node, source))
                analysis.symbols.append(sym)

                if name == "main":
                    analysis.has_main = True

        elif ntype == "struct_item":
            name_node = node.child_by_field_name("name")
            if name_node:
                analysis.symbols.append(TSSymbol(
                    name=_node_text(name_node, source),
                    kind="struct",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                ))

        elif ntype == "impl_item":
            # Extract methods from impl blocks
            type_node = node.child_by_field_name("type")
            parent_name = _node_text(type_node, source) if type_node else None
            body = node.child_by_field_name("body")
            if body:
                for child in body.children:
                    if child.type == "function_item":
                        fn_name_node = child.child_by_field_name("name")
                        if fn_name_node:
                            name = _node_text(fn_name_node, source)
                            sym = TSSymbol(
                                name=name,
                                kind="method",
                                start_line=child.start_point[0] + 1,
                                end_line=child.end_point[0] + 1,
                                parent=parent_name,
                            )
                            _tag_security_relevance(sym, _node_text(child, source))
                            analysis.symbols.append(sym)


def _extract_generic_ts(root, source: bytes, analysis: TSFileAnalysis):
    """Generic extraction for unsupported languages — extract functions and classes."""
    for node in _walk(root):
        ntype = node.type
        if "function" in ntype or "method" in ntype:
            name_node = node.child_by_field_name("name")
            if name_node:
                sym = TSSymbol(
                    name=_node_text(name_node, source),
                    kind="function" if "function" in ntype else "method",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                )
                analysis.symbols.append(sym)
        elif "class" in ntype:
            name_node = node.child_by_field_name("name")
            if name_node:
                analysis.symbols.append(TSSymbol(
                    name=_node_text(name_node, source),
                    kind="class",
                    start_line=node.start_point[0] + 1,
                    end_line=node.end_point[0] + 1,
                ))


# --- Call Site Extraction (language-agnostic) ---

# AST node types that represent function/method calls in various languages
CALL_NODE_TYPES = {
    "call",                  # Python
    "call_expression",       # JS/TS, Go, Rust
    "method_invocation",     # Java
    "invocation_expression", # C#
}

# Language keywords that look like calls but aren't
CALL_EXCLUDE = {
    "if", "for", "while", "switch", "case", "return", "yield", "await",
    "print", "len", "str", "int", "float", "bool", "list", "dict", "set",
    "tuple", "type", "super", "self", "this", "new", "typeof", "instanceof",
    "assert", "raise", "throw", "class", "def", "function", "var", "let",
    "const", "import", "from", "export", "catch", "finally",
}


def _extract_call_sites(root, source: bytes, analysis: TSFileAnalysis):
    """
    Extract all function/method call sites from the AST.
    Works across all languages by looking for common call node types.
    Maps each call to its enclosing symbol (function/method).
    """
    for node in _walk(root):
        if node.type not in CALL_NODE_TYPES:
            continue

        line = node.start_point[0] + 1
        callee_name = None
        callee_object = None
        is_method = False
        arg_count = 0
        full_expr = ""

        # Get the function/callee part of the call
        func_node = node.child_by_field_name("function")
        if not func_node:
            # Some languages use different field names
            func_node = node.child_by_field_name("name")
        if not func_node:
            # Try first child as fallback
            if node.children:
                func_node = node.children[0]

        if not func_node:
            continue

        func_text = _node_text(func_node, source)

        # Determine if it's a method call (obj.method) or plain call (func)
        if func_node.type in ("attribute", "member_expression", "field_expression", "selector_expression"):
            # Method call: obj.method()
            is_method = True
            obj_node = func_node.child_by_field_name("object")
            attr_node = func_node.child_by_field_name("attribute") or func_node.child_by_field_name("property") or func_node.child_by_field_name("field")

            if attr_node:
                callee_name = _node_text(attr_node, source)
            if obj_node:
                callee_object = _node_text(obj_node, source)

            full_expr = func_text
        elif func_node.type == "identifier":
            # Plain function call: func()
            callee_name = func_text
            full_expr = callee_name
        elif func_node.type == "scoped_identifier":
            # Rust: module::function()
            callee_name = func_text.rsplit("::", 1)[-1] if "::" in func_text else func_text
            callee_object = func_text.rsplit("::", 1)[0] if "::" in func_text else None
            is_method = True
            full_expr = func_text
        else:
            # Fallback: use the text
            callee_name = func_text.split("(")[0].split(".")[-1].strip()
            full_expr = func_text

        if not callee_name or callee_name in CALL_EXCLUDE:
            continue

        # Count arguments
        args_node = node.child_by_field_name("arguments")
        if args_node:
            arg_count = sum(1 for c in args_node.children if c.type not in ("(", ")", ",", "comment"))

        # Find enclosing symbol
        enclosing = _find_enclosing_symbol(node, analysis.symbols, line)

        analysis.call_sites.append(TSCallSite(
            callee_name=callee_name,
            callee_object=callee_object,
            line=line,
            enclosing_symbol=enclosing,
            argument_count=arg_count,
            is_method_call=is_method,
            full_expression=full_expr[:100],
        ))


def _find_enclosing_symbol(node, symbols: list[TSSymbol], line: int) -> str | None:
    """Find which function/method contains the given line number."""
    best = None
    best_size = float("inf")
    for sym in symbols:
        if sym.kind in ("function", "method") and sym.start_line <= line <= sym.end_line:
            size = sym.end_line - sym.start_line
            if size < best_size:
                best = sym.name
                best_size = size
    return best


# --- Helpers ---

def _walk(node):
    """Yield all nodes in a tree-sitter tree via depth-first traversal."""
    yield node
    for child in node.children:
        yield from _walk(child)


def _find_parent_class(node) -> str | None:
    """Walk up the tree to find enclosing class name."""
    current = node.parent
    while current:
        if current.type in ("class_definition", "class_declaration"):
            name_node = current.child_by_field_name("name")
            if name_node:
                return name_node.text.decode("utf-8", errors="replace")
        current = current.parent
    return None


def _find_parent_class_js(node) -> str | None:
    """Walk up the tree to find enclosing class in JS/TS."""
    current = node.parent
    while current:
        if current.type == "class_declaration":
            name_node = current.child_by_field_name("name")
            if name_node:
                return name_node.text.decode("utf-8", errors="replace")
        current = current.parent
    return None


# Security-relevant patterns for tagging
import re

_SECURITY_TAGS = {
    "auth": re.compile(r"(?i)(authenticate|authorize|login|logout|session|jwt|oauth|rbac|permission)"),
    "crypto": re.compile(r"(?i)(encrypt|decrypt|hash|sign|verify|hmac|aes|rsa|sha|bcrypt|argon|scrypt)"),
    "db_access": re.compile(r"(?i)(query|execute|cursor|select\s|insert\s|update\s|delete\s|\.find|\.save|\.create)"),
    "file_io": re.compile(r"(?i)(open\(|read_file|write_file|upload|download|path\.join|sendFile|readFile|writeFile)"),
    "command_exec": re.compile(r"(?i)(exec|spawn|system|popen|subprocess|shell|child_process|Command::new)"),
    "deserialization": re.compile(r"(?i)(deseriali[sz]e|unmarshal|unpickle|yaml\.load|json\.parse|fromJSON|decode)"),
    "network": re.compile(r"(?i)(http\.get|http\.post|fetch\(|request\(|urllib|httpx|reqwest|net\.dial)"),
    "template": re.compile(r"(?i)(render|template|innerHTML|dangerouslySetInnerHTML|v-html|safe\|)"),
    "input_handling": re.compile(r"(?i)(request\.|req\.|params\[|\.body\[|\.query\[|form_data|getParameter)"),
    "redirect": re.compile(r"(?i)(redirect|location\.href|window\.location|res\.redirect)"),
    "cookie": re.compile(r"(?i)(cookie|set-cookie|setCookie|document\.cookie)"),
    "cors": re.compile(r"(?i)(cors|access-control|cross-origin)"),
    "rate_limit": re.compile(r"(?i)(rate.?limit|throttle|limiter)"),
}


def _tag_security_relevance(sym: TSSymbol, body_text: str):
    """Tag a symbol with security-relevant markers based on its body text."""
    text_to_check = (sym.name + " " + (sym.signature or "") + " " + body_text[:2000]).lower()
    for tag_name, pattern in _SECURITY_TAGS.items():
        if pattern.search(text_to_check):
            sym.tags[tag_name] = True


def get_symbol_body(content: str, symbol: TSSymbol) -> str:
    """Extract the body text of a symbol from file content."""
    lines = content.splitlines()
    start = max(0, symbol.start_line - 1)
    end = min(len(lines), symbol.end_line)
    return "\n".join(lines[start:end])
