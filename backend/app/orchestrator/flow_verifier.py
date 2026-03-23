"""Helpers for grounding taint flows against the static call graph."""

from app.orchestrator.scan_context import TaintFlow


def verify_taint_flow_graph(flow: TaintFlow, call_graph, file_analyses: dict, *, max_depth: int = 6) -> bool:
    """Try to confirm a taint flow using the pre-built static call graph."""
    if not call_graph or not file_analyses:
        return False

    src_symbols = _symbols_for_line(file_analyses.get(flow.source_file), flow.source_line)
    sink_symbols = _symbols_for_line(file_analyses.get(flow.sink_file), flow.sink_line)

    if not src_symbols or not sink_symbols:
        return False

    best_path = None
    best_pair = None

    for src_symbol in src_symbols:
        for sink_symbol in sink_symbols:
            path = call_graph.find_path(
                flow.source_file,
                src_symbol,
                flow.sink_file,
                sink_symbol,
                max_depth=max_depth,
            )
            if path is None:
                continue
            if best_path is None or len(path) < len(best_path):
                best_path = path
                best_pair = (src_symbol, sink_symbol)
            if path == []:
                break

    if best_path is None:
        return False

    flow.graph_verified = True
    flow.call_chain = [
        {
            "caller_file": edge.caller_file,
            "caller_symbol": edge.caller_symbol,
            "caller_line": edge.caller_line,
            "callee_file": edge.callee_file,
            "callee_symbol": edge.callee_symbol,
            "resolution_type": edge.resolution_type,
            "confidence": edge.confidence,
        }
        for edge in best_path
    ]

    if not flow.intermediaries:
        if best_path:
            flow.intermediaries = [
                f"{edge.caller_symbol} -> {edge.callee_symbol}"
                for edge in best_path
            ]
        elif best_pair:
            flow.intermediaries = [f"{best_pair[0]} -> {best_pair[1]}"]

    return True


def format_call_chain(flow: TaintFlow) -> str:
    """Render a human-readable call chain summary for prompts and logs."""
    if not flow.call_chain:
        return "Direct path within the same symbol."

    steps = []
    for edge in flow.call_chain:
        steps.append(
            f"{edge.get('caller_file')}::{edge.get('caller_symbol')} -> "
            f"{edge.get('callee_file')}::{edge.get('callee_symbol')}"
        )
    return "\n".join(f"- {step}" for step in steps)


def _symbols_for_line(analysis, line: int) -> list[str]:
    if not analysis or line <= 0:
        return []

    candidates = [
        symbol
        for symbol in getattr(analysis, "symbols", [])
        if symbol.kind in ("function", "method")
        and symbol.start_line <= line <= symbol.end_line
    ]
    if not candidates:
        candidates = [
            symbol
            for symbol in getattr(analysis, "symbols", [])
            if symbol.kind in ("function", "method")
            and symbol.start_line <= line
        ]

    candidates.sort(
        key=lambda symbol: (
            max(0, symbol.end_line - symbol.start_line),
            abs(symbol.start_line - line),
        )
    )
    return [symbol.name for symbol in candidates[:5]]
