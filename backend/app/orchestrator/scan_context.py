"""Shared scan context — the orchestrator's working memory."""

import uuid
from dataclasses import dataclass, field


@dataclass
class CandidateFinding:
    """A potential finding being investigated."""

    title: str
    category: str
    severity: str
    file_path: str
    line_range: str | None = None
    code_snippet: str | None = None
    hypothesis: str = ""
    supporting_evidence: list[str] = field(default_factory=list)
    opposing_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.5
    status: str = "investigating"  # investigating, confirmed, dismissed
    provenance: str = "llm"  # llm, scanner, hybrid
    source_scanners: list[str] = field(default_factory=list)
    source_rules: list[str] = field(default_factory=list)
    source_scanner_hits: list[dict] = field(default_factory=list)
    verification_level: str = "hypothesis"  # hypothesis, statically_verified, strongly_verified, runtime_validated, dismissed
    verification_notes: str = ""
    canonical_key: str | None = None
    merge_metadata: dict | None = None
    related_findings: list[str] = field(default_factory=list)  # IDs of related findings
    input_sources: list[str] = field(default_factory=list)  # Traced input entry points
    sinks: list[str] = field(default_factory=list)  # Where tainted data is consumed
    # CWE references
    cwe_ids: list[str] = field(default_factory=list)  # e.g. ["CWE-89", "CWE-564"]
    # Exploit evidence (populated by verifier)
    exploit_difficulty: str = ""  # easy, moderate, difficult, theoretical
    exploit_prerequisites: list[str] = field(default_factory=list)
    exploit_template: str = ""  # PoC code (curl, Python, etc.)
    attack_scenario: str = ""  # Step-by-step exploitation narrative
    exploit_evidence: dict | None = None  # Structured PoC metadata for reporting/export
    # CVE correlation (populated by verifier's CVE correlation step)
    related_cves: list[dict] = field(default_factory=list)  # [{cve_id, summary, severity, package}]
    finding_id: str | None = None  # Persisted finding UUID once stored in the database


@dataclass
class TaintFlow:
    """A tracked data flow from source to sink across files."""

    source_file: str
    source_line: int
    source_type: str  # request_param, env_var, file_read, db_query, etc.
    sink_file: str
    sink_line: int
    sink_type: str  # sql_exec, os_exec, template_render, file_write, etc.
    intermediaries: list[str] = field(default_factory=list)  # files/functions between
    confidence: float = 0.5
    sanitised: bool = False
    sanitiser_location: str | None = None
    call_chain: list | None = None  # Verified call chain from call graph
    graph_verified: bool = False  # Whether the call graph confirms reachability


@dataclass
class FileScore:
    """Score and metadata for a file, used for adaptive prioritisation."""

    path: str
    static_score: float = 0.0
    dynamic_boost: float = 0.0  # Boost from findings/references during scan
    scanner_hits: int = 0
    referenced_by: int = 0  # How many findings reference this file
    last_inspected_pass: int = -1

    @property
    def effective_score(self) -> float:
        return self.static_score + self.dynamic_boost


@dataclass
class ScanContext:
    """
    Mutable state object for a running scan.
    Agents read and write this shared context.
    """

    scan_id: uuid.UUID
    project_id: uuid.UUID
    repo_path: str
    mode: str  # light, regular, heavy

    # Phase tracking
    current_phase: str = "triage"
    current_task: str = ""

    # Source type (from project)
    source_type: str = "codebase"  # codebase, apk, aab, dex, jar

    # Repo fingerprint
    fingerprint: dict = field(default_factory=dict)
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    app_type: str = ""  # e.g., "web_app", "api", "cli", "library"

    # Monorepo / workspace info
    is_monorepo: bool = False
    workspaces: list[dict] = field(default_factory=list)  # [{name, path, type, manifest}]

    # Obfuscation tracking
    obfuscation_summary: dict = field(default_factory=dict)  # From summarise_obfuscation()
    obfuscated_files: set[str] = field(default_factory=set)  # Paths with score >= 0.4
    non_analysable_files: set[str] = field(default_factory=set)  # Paths with score >= 0.7

    # Repo size overflow tracking
    files_skipped_size: int = 0  # Files skipped because they exceed max_file_size
    files_skipped_cap: int = 0  # Files not indexed because repo exceeded max_files
    size_warnings: list[str] = field(default_factory=list)

    # File tracking with adaptive scoring
    files_total: int = 0
    files_processed: int = 0
    file_queue: list[str] = field(default_factory=list)  # Ordered by priority
    file_scores: dict[str, FileScore] = field(default_factory=dict)
    files_inspected: set[str] = field(default_factory=set)

    # Documentation intelligence (extracted from READMEs, docs, etc.)
    doc_intelligence: str = ""  # Compact AI-generated summary of project documentation
    doc_files_found: list[str] = field(default_factory=list)  # Paths to discovered doc files

    # App understanding
    app_summary: str = ""
    architecture_notes: str = ""
    diagram_spec: str = ""
    attack_surface: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    entry_points: list[dict] = field(default_factory=list)  # {file, function, type}
    components: list[dict] = field(default_factory=list)  # From architecture agent
    scoped_attack_surface: set[str] = field(default_factory=set)  # Files in attack surface

    # Scanner instances (created once per scan, reused across agents)
    scanners: dict = field(default_factory=dict)  # name -> ScannerAdapter instance
    scanner_config: dict[str, bool] = field(default_factory=dict)  # name -> enabled by scan config
    scanner_availability: dict[str, str] = field(default_factory=dict)  # name -> enabled/disabled/unavailable

    # Scanner results summary
    scanner_hit_counts: dict[str, int] = field(default_factory=dict)
    scanner_runs: dict[str, dict] = field(default_factory=dict)  # name -> run status summary
    degraded_coverage: bool = False
    baseline_rule_dirs: list[str] = field(default_factory=list)  # Semgrep dirs used in baseline
    baseline_rule_count: int = 0

    # Repo scope / ignore tracking
    repo_ignore_file: str | None = None
    ignored_paths: list[str] = field(default_factory=list)
    managed_paths_ignored: list[str] = field(default_factory=list)
    ignored_file_count: int = 0

    # Call graph and import resolution (built during triage, no LLM needed)
    call_graph: object | None = None  # CallGraph instance (from app.analysis.call_graph)
    import_graph: dict = field(default_factory=dict)  # file_path -> [ImportResolution]
    file_analyses: dict = field(default_factory=dict)  # file_path -> TSFileAnalysis

    # Dependency cache (populated by dependency agent, used by investigator)
    _dep_cache: dict = field(default_factory=dict)

    # Investigation state
    candidate_findings: list[CandidateFinding] = field(default_factory=list)
    taint_flows: list[TaintFlow] = field(default_factory=list)
    compaction_summaries: list[str] = field(default_factory=list)
    key_observations: list[str] = field(default_factory=list)
    current_pass: int = 0

    # Counters
    ai_calls_made: int = 0
    tokens_used: int = 0
    findings_count: int = 0

    # Cancellation flag
    cancelled: bool = False

    @property
    def iteration_budget(self) -> dict:
        """Return iteration limits based on scan mode, with adaptive scaling."""
        base = {
            "light": {
                "phase2_file_reads": 10,
                "phase3_passes": 1,
                "phase3_files_per_pass": 8,
                "related_file_hops": 1,
                "targeted_reruns": 0,
                "max_ai_calls": 30,
                "verification_depth": "shallow",
            },
            "regular": {
                "phase2_file_reads": 30,
                "phase3_passes": 3,
                "phase3_files_per_pass": 15,
                "related_file_hops": 3,
                "targeted_reruns": 2,
                "max_ai_calls": 100,
                "verification_depth": "standard",
            },
            "heavy": {
                "phase2_file_reads": 80,
                "phase3_passes": 6,
                "phase3_files_per_pass": 30,
                "related_file_hops": 4,
                "targeted_reruns": 5,
                "max_ai_calls": 300,
                "verification_depth": "deep",
            },
        }
        budget = base.get(self.mode, base["regular"]).copy()

        # ── Adaptive scaling ─────────────────────────────────────
        # If the repo is large, increase file budget proportionally
        if self.files_total > 500:
            scale = min(2.0, self.files_total / 500)
            budget["phase2_file_reads"] = int(budget["phase2_file_reads"] * scale)
            budget["phase3_files_per_pass"] = int(budget["phase3_files_per_pass"] * scale)

        # If finding density is high, add extra investigation passes
        if len(self.candidate_findings) > 10 and self.mode != "light":
            budget["phase3_passes"] += 1

        # If we found taint flows, allow deeper hops to trace them
        if len(self.taint_flows) > 3:
            budget["related_file_hops"] += 1

        return budget

    def reprioritise_queue(self):
        """
        Re-sort the file queue based on dynamic boosts from findings.
        Called after each investigation pass to ensure the most relevant
        files are inspected next.
        """
        def score_key(path: str) -> float:
            fs = self.file_scores.get(path)
            if not fs:
                return 0.0
            return fs.effective_score

        uninspected = [f for f in self.file_queue if f not in self.files_inspected]
        uninspected.sort(key=score_key, reverse=True)
        self.file_queue = uninspected

    def boost_file(self, file_path: str, boost: float, reason: str = ""):
        """Dynamically boost a file's priority during investigation."""
        if file_path in self.file_scores:
            self.file_scores[file_path].dynamic_boost += boost
            self.file_scores[file_path].referenced_by += 1
        else:
            self.file_scores[file_path] = FileScore(
                path=file_path,
                dynamic_boost=boost,
                referenced_by=1,
            )

    def record_scanner_run(
        self,
        scanner_name: str,
        *,
        success: bool,
        hit_count: int,
        duration_ms: int,
        errors: list[str] | None = None,
        status: str | None = None,
    ) -> dict:
        """Record a scanner execution summary for reporting and UI surfaces."""
        cleaned_errors = [e.strip() for e in (errors or []) if isinstance(e, str) and e.strip()]
        resolved_status = status
        if not resolved_status:
            if not success:
                resolved_status = "failed"
            elif cleaned_errors:
                resolved_status = "degraded"
            else:
                resolved_status = "completed"

        summary = {
            "scanner": scanner_name,
            "status": resolved_status,
            "success": success,
            "hit_count": hit_count,
            "duration_ms": duration_ms,
            "errors": cleaned_errors,
        }
        self.scanner_runs[scanner_name] = summary
        self.scanner_hit_counts[scanner_name] = hit_count
        if resolved_status in {"failed", "degraded"}:
            self.degraded_coverage = True
        return summary

    def get_hot_files(self, limit: int = 10) -> list[str]:
        """
        Get files that have been dynamically boosted by findings
        but not yet inspected. These are the most promising leads.
        """
        boosted = [
            (path, fs) for path, fs in self.file_scores.items()
            if fs.dynamic_boost > 0 and path not in self.files_inspected
        ]
        boosted.sort(key=lambda x: x[1].effective_score, reverse=True)
        return [path for path, _ in boosted[:limit]]

    def get_finding_clusters(self) -> list[list[CandidateFinding]]:
        """
        Group candidate findings that are likely related —
        same file, same category, or overlapping code areas.
        Useful for cross-finding correlation.
        """
        clusters: list[list[CandidateFinding]] = []
        assigned: set[int] = set()

        for i, f1 in enumerate(self.candidate_findings):
            if i in assigned:
                continue
            cluster = [f1]
            assigned.add(i)

            for j, f2 in enumerate(self.candidate_findings):
                if j in assigned:
                    continue
                # Same file or same category + nearby file
                if (
                    f1.file_path == f2.file_path
                    or f1.category == f2.category
                    or _files_related(f1.file_path, f2.file_path)
                ):
                    cluster.append(f2)
                    assigned.add(j)

            if len(cluster) > 1:
                clusters.append(cluster)

        return clusters


def _files_related(path1: str, path2: str) -> bool:
    """Check if two files are in the same directory (likely related)."""
    parts1 = path1.rsplit("/", 1)
    parts2 = path2.rsplit("/", 1)
    if len(parts1) > 1 and len(parts2) > 1:
        return parts1[0] == parts2[0]
    return False
