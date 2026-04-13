export interface Project {
  id: string;
  name: string;
  description: string | null;
  repo_path: string;
  source_type: "codebase" | "apk" | "aab" | "dex" | "jar";
  created_at: string;
  updated_at: string;
  scan_count: number;
}

export interface Scan {
  id: string;
  project_id: string;
  mode: "light" | "regular" | "heavy";
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  current_phase: string | null;
  current_task: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  error_message: string | null;
  files_processed: number;
  files_total: number;
  findings_count: number;
  progress: number;
  ai_calls_made: number;
}

export interface ScanEvent {
  id: number;
  phase: string | null;
  level: "debug" | "info" | "warn" | "error";
  message: string;
  detail: Record<string, unknown> | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: number;
  category: string | null;
  description: string;
  explanation: string | null;
  impact: string | null;
  remediation: string | null;
  code_snippet: string | null;
  status: string;
  cwe_ids: string[] | null;
  related_cves: RelatedAdvisory[] | null;
  exploit_difficulty: string | null;
  exploit_prerequisites: string[] | null;
  exploit_template: string | null;
  attack_scenario: string | null;
  exploit_evidence: ExploitEvidence | null;
  provenance?: "llm" | "scanner" | "hybrid" | string | null;
  source_scanners?: string[] | null;
  source_rules?: string[] | null;
  verification_level?: string | null;
  verification_notes?: string | null;
  canonical_key?: string | null;
  merge_metadata?: Record<string, unknown> | null;
  evidence: Evidence[];
  file_paths: string[];
  created_at: string;
}

export interface ExploitEvidence {
  difficulty?: string | null;
  target_route?: string | null;
  prerequisites?: string[] | null;
  validation_steps?: string[] | null;
  cleanup_notes?: string[] | null;
  exploit_template?: string | null;
  attack_scenario?: string | null;
  components?: string[] | null;
  related_entry_points?: string[] | null;
  related_taint_flows?: string[] | null;
}

export interface Evidence {
  id: string;
  type: "supporting" | "opposing" | "contextual";
  description: string;
  code_snippet: string | null;
  line_range: string | null;
  source: string | null;
}

export interface Report {
  id: string;
  scan_id: string;
  app_summary: string | null;
  architecture: string | null;
  diagram_spec: string | null;
  has_diagram_image: boolean;
  diagram_count?: number;
  diagram_media_type?: string | null;
  narrative: string | null;
  methodology: string | null;
  limitations: string | null;
  tech_stack: Record<string, unknown> | null;
  scanner_hits: Record<string, number> | null;
  attack_surface: Record<string, number> | null;
  risk_score: number | null;
  risk_grade: string | null;
  owasp_mapping: Record<string, OWASPEntry> | null;
  component_scores: Record<string, ComponentScore> | null;
  sbom: SBOMData | null;
  scan_coverage: ScanCoverage | null;
  created_at: string;
}

export interface ScannerRunSummary {
  scanner: string;
  status: "completed" | "degraded" | "failed" | "skipped";
  success: boolean;
  hit_count: number;
  duration_ms: number;
  errors: string[];
}

export interface OWASPEntry {
  name: string;
  count: number;
  findings: string[];
  max_severity: string;
}

export interface ComponentScore {
  score: number;
  grade: string;
  criticality: string;
  finding_count: number;
  severities: Record<string, number>;
  in_attack_surface: boolean;
}

export interface SBOMData {
  total_components: number;
  vulnerable_components: number;
  ecosystems: Record<string, number>;
  components: SBOMComponent[];
}

export interface SBOMComponent {
  name: string;
  version: string | null;
  ecosystem: string;
  source_file: string | null;
  is_dev: boolean;
  vulnerable: boolean;
  vulnerability_count: number;
}

export interface ScanCoverage {
  total_files: number;
  files_indexed: number;
  files_inspected_by_ai: number;
  files_skipped_size: number;
  files_skipped_cap: number;
  scanners_used: string[];
  scanner_runs?: Record<string, ScannerRunSummary>;
  degraded_coverage?: boolean;
  ai_calls_made: number;
  scan_mode: string;
  obfuscated_files: number;
  is_monorepo: boolean;
  is_apk: boolean;
  doc_files_read: number;
  has_doc_intelligence: boolean;
  ignored_file_count?: number;
  ignored_paths?: string[];
  managed_paths_ignored?: string[];
  repo_ignore_file?: string | null;
}

export interface LLMProfile {
  id: string;
  name: string;
  base_url: string;
  api_key_set: boolean;
  model_name: string;
  cert_path: string | null;
  timeout_seconds: number;
  context_window: number;
  max_output_tokens: number;
  use_max_completion_tokens: boolean;
  concurrency: number;
  is_default: boolean;
  created_at: string;
}

export interface SecretCandidate {
  id: string;
  type: string;
  value_preview: string | null;
  line_number: number | null;
  confidence: number | null;
  context: string | null;
  file_path: string | null;
  is_false_positive: boolean;
}

export interface RelatedAdvisory {
  display_id?: string | null;
  advisory_id?: string | null;
  cve_id?: string | null;
  package: string;
  ecosystem?: string | null;
  severity: string;
  summary: string;
  fixed_version?: string | null;
  evidence_type?: string | null;
  evidence_strength?: string | null;
  package_evidence_source?: string | null;
  package_match_confidence?: number | null;
  import_module?: string | null;
  imported_symbol?: string | null;
  call_object?: string | null;
  function?: string | null;
  line?: number | null;
  cwe_ids?: string[] | null;
  evidence_types?: string[] | null;
  evidence_sources?: string[] | null;
}

export type DependencyRelevance =
  | "used"
  | "likely_used"
  | "transitive_only"
  | "test_only"
  | "unknown"
  | "unused";

export type DependencyReachability =
  | "reachable"
  | "potentially_reachable"
  | "no_path_found"
  | "not_applicable"
  | "unknown";

export interface DependencyUsageEvidence {
  file: string;
  kind?: string | null;
  symbol?: string | null;
  confidence?: number | null;
  source?: string | null;
  line?: number | null;
}

export interface DependencyFinding {
  id: string;
  package_name: string;
  ecosystem: string;
  installed_version: string | null;
  advisory_id: string | null;
  severity: string | null;
  cvss_score: number | null;
  summary: string | null;
  affected_range: string | null;
  fixed_version: string | null;
  vulnerable_functions?: string[] | null;
  evidence_type: string;
  relevance: DependencyRelevance | string;
  usage_evidence?: DependencyUsageEvidence[] | null;
  reachability_status: DependencyReachability | string;
  reachability_confidence?: number | null;
  risk_score?: number | null;
  risk_factors?: Record<string, number | string | boolean | null> | null;
  ai_assessment: string | null;
}

export interface ScanProgress {
  scan_id: string;
  status: string;
  phase: string | null;
  task: string | null;
  files_processed: number;
  files_total: number;
  findings_count: number;
  elapsed_seconds: number;
}

export interface WSEvent {
  type: "event" | "progress";
  phase?: string;
  task?: string;
  level?: string;
  message?: string;
  detail?: Record<string, unknown>;
  status?: string;
  findings_count?: number;
  files_processed?: number;
  files_total?: number;
  ai_calls_made?: number;
  error?: string;
}
