"""Call graph builder — constructs cross-file function call relationships.

Combines call site extraction (which function calls what) with import
resolution (which import maps to which file) to build a queryable graph
of inter-procedural call relationships.

Designed for speed, not completeness. Handles:
- Direct same-file calls (function A calls function B in the same file)
- Import-resolved calls (function A calls imported function B from another file)
- Method calls on imported objects (obj.method() where obj is an import)

Does NOT handle:
- Virtual dispatch / polymorphism
- Dynamic calls (eval, getattr, reflection)
- Callback passing (function passed as argument)
- Higher-order functions

The AI investigator handles these complex cases. The call graph provides
deterministic verification for the simple cases, which covers ~70% of
real-world call chains in security-relevant code.
"""

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CallEdge:
    """A verified call relationship between two functions."""

    caller_file: str
    caller_symbol: str
    caller_line: int
    callee_file: str
    callee_symbol: str
    resolution_type: str  # "direct" (same file), "import", "method", "heuristic"
    confidence: float  # 0.0 - 1.0


@dataclass
class CallGraph:
    """
    Queryable call graph with pre-built indexes.

    Use callers_of() to find who calls a function.
    Use callees_of() to find what a function calls.
    Use find_path() to find a call chain between two functions.
    """

    edges: list[CallEdge] = field(default_factory=list)

    # Pre-built indexes (populated by build())
    _callers: dict[tuple[str, str], list[CallEdge]] = field(default_factory=lambda: defaultdict(list))
    _callees: dict[tuple[str, str], list[CallEdge]] = field(default_factory=lambda: defaultdict(list))
    _file_callers: dict[str, list[CallEdge]] = field(default_factory=lambda: defaultdict(list))
    _file_callees: dict[str, list[CallEdge]] = field(default_factory=lambda: defaultdict(list))

    def _rebuild_indexes(self):
        self._callers = defaultdict(list)
        self._callees = defaultdict(list)
        self._file_callers = defaultdict(list)
        self._file_callees = defaultdict(list)

        for edge in self.edges:
            self._callers[(edge.callee_file, edge.callee_symbol)].append(edge)
            self._callees[(edge.caller_file, edge.caller_symbol)].append(edge)
            self._file_callers[edge.callee_file].append(edge)
            self._file_callees[edge.caller_file].append(edge)

    def callers_of(self, file: str, symbol: str) -> list[CallEdge]:
        """Find all functions that call the given symbol."""
        return self._callers.get((file, symbol), [])

    def callees_of(self, file: str, symbol: str) -> list[CallEdge]:
        """Find all functions called by the given symbol."""
        return self._callees.get((file, symbol), [])

    def get_file_callers(self, file: str) -> list[CallEdge]:
        """Get all incoming call edges to functions in this file."""
        return self._file_callers.get(file, [])

    def get_file_callees(self, file: str) -> list[CallEdge]:
        """Get all outgoing call edges from functions in this file."""
        return self._file_callees.get(file, [])

    def find_path(
        self,
        from_file: str,
        from_symbol: str,
        to_file: str,
        to_symbol: str,
        max_depth: int = 6,
    ) -> list[CallEdge] | None:
        """
        BFS to find a call chain from one function to another.
        Returns the shortest path as a list of edges, or None if unreachable.
        """
        start = (from_file, from_symbol)
        end = (to_file, to_symbol)

        if start == end:
            return []

        queue = deque([(start, [])])
        visited = {start}

        while queue:
            current, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            for edge in self._callees.get(current, []):
                next_node = (edge.callee_file, edge.callee_symbol)

                if next_node == end:
                    return path + [edge]

                if next_node not in visited:
                    visited.add(next_node)
                    queue.append((next_node, path + [edge]))

        return None

    def get_entry_points_reaching(
        self,
        file: str,
        symbol: str,
        entry_point_tags: set[str] | None = None,
        max_depth: int = 8,
    ) -> list[list[CallEdge]]:
        """
        Trace backwards from a function to find all entry points
        (route handlers, main functions) that can reach it.
        Returns a list of paths (each path is a list of edges).
        """
        if entry_point_tags is None:
            entry_point_tags = {"entrypoint", "auth", "network", "input_handling"}

        target = (file, symbol)
        paths = []
        queue = deque([(target, [])])
        visited = {target}

        while queue:
            current, path = queue.popleft()

            if len(path) >= max_depth:
                continue

            callers = self._callers.get(current, [])

            if not callers and path:
                # No more callers — this might be an entry point
                paths.append(list(reversed(path)))
                continue

            for edge in callers:
                prev_node = (edge.caller_file, edge.caller_symbol)
                if prev_node not in visited:
                    visited.add(prev_node)
                    queue.append((prev_node, path + [edge]))

        return paths

    def get_high_indegree_files(
        self, *, limit: int = 10, uninspected: set[str] | None = None
    ) -> list[tuple[str, int]]:
        """Get files with the most incoming call edges (most called)."""
        counts: dict[str, int] = defaultdict(int)
        for (file, _), edges in self._callers.items():
            if uninspected and file not in uninspected:
                continue
            counts[file] += len(edges)

        return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]


class CallGraphBuilder:
    """
    Builds a CallGraph from file analyses and import resolutions.
    """

    def __init__(
        self,
        file_analyses: dict[str, "TSFileAnalysis"],
        import_resolutions: dict[str, list["ImportResolution"]],
    ):
        self._analyses = file_analyses
        self._imports = import_resolutions

        # Build symbol lookup: (file, name) -> True
        self._symbols: dict[tuple[str, str], bool] = {}
        for file_path, analysis in file_analyses.items():
            for sym in analysis.symbols:
                self._symbols[(file_path, sym.name)] = True

        # Build import name → resolved file mapping per file
        self._import_map: dict[str, dict[str, str]] = {}  # file -> {name: resolved_path}
        for file_path, resolutions in import_resolutions.items():
            mapping = {}
            for res in resolutions:
                if res.resolved_path:
                    # Map the imported name(s) to the resolved file
                    for name in res.imported_names:
                        mapping[name] = res.resolved_path
                    # Also map the module itself
                    module_name = res.import_module.rsplit(".", 1)[-1].rsplit("/", 1)[-1]
                    mapping[module_name] = res.resolved_path
            self._import_map[file_path] = mapping

    def build(self) -> CallGraph:
        """Build the call graph from all file analyses."""
        graph = CallGraph()

        for file_path, analysis in self._analyses.items():
            for call_site in analysis.call_sites:
                edge = self._resolve_call(file_path, analysis, call_site)
                if edge:
                    graph.edges.append(edge)

        graph._rebuild_indexes()

        logger.info(
            "Call graph built: %d edges across %d files",
            len(graph.edges),
            len(self._analyses),
        )

        return graph

    def _resolve_call(
        self, caller_file: str, analysis, call_site
    ) -> CallEdge | None:
        """Try to resolve a single call site to a call edge."""
        callee_name = call_site.callee_name
        callee_obj = call_site.callee_object
        enclosing = call_site.enclosing_symbol or "<module>"

        # 1. Same-file call: callee defined in this file
        if (caller_file, callee_name) in self._symbols:
            return CallEdge(
                caller_file=caller_file,
                caller_symbol=enclosing,
                caller_line=call_site.line,
                callee_file=caller_file,
                callee_symbol=callee_name,
                resolution_type="direct",
                confidence=1.0,
            )

        # 2. Import-resolved call: callee name matches an import
        import_map = self._import_map.get(caller_file, {})

        if callee_name in import_map:
            target_file = import_map[callee_name]
            # Verify the symbol exists in the target file
            if (target_file, callee_name) in self._symbols:
                return CallEdge(
                    caller_file=caller_file,
                    caller_symbol=enclosing,
                    caller_line=call_site.line,
                    callee_file=target_file,
                    callee_symbol=callee_name,
                    resolution_type="import",
                    confidence=0.9,
                )
            else:
                # Import resolves to a file but symbol not found (might be re-exported)
                return CallEdge(
                    caller_file=caller_file,
                    caller_symbol=enclosing,
                    caller_line=call_site.line,
                    callee_file=target_file,
                    callee_symbol=callee_name,
                    resolution_type="import",
                    confidence=0.5,
                )

        # 3. Method call on imported object: obj.method()
        if callee_obj and callee_obj in import_map:
            target_file = import_map[callee_obj]
            target_analysis = self._analyses.get(target_file)
            if target_analysis:
                # Look for a method with the callee name in the target file
                for sym in target_analysis.symbols:
                    if sym.name == callee_name and sym.kind in ("method", "function"):
                        return CallEdge(
                            caller_file=caller_file,
                            caller_symbol=enclosing,
                            caller_line=call_site.line,
                            callee_file=target_file,
                            callee_symbol=callee_name,
                            resolution_type="method",
                            confidence=0.7,
                        )

        # 4. Heuristic: unique symbol name across the whole repo
        matches = [
            (f, s) for (f, s), _ in self._symbols.items()
            if s == callee_name and f != caller_file
        ]
        if len(matches) == 1:
            target_file, target_sym = matches[0]
            return CallEdge(
                caller_file=caller_file,
                caller_symbol=enclosing,
                caller_line=call_site.line,
                callee_file=target_file,
                callee_symbol=target_sym,
                resolution_type="heuristic",
                confidence=0.3,
            )

        # Unresolvable — skip silently
        return None
