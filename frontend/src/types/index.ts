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
  related_cves: Array<{ cve_id: string; package: string; severity: string; summary: string; fixed_version?: string }> | null;
  exploit_difficulty: string | null;
  exploit_prerequisites: string[] | null;
  exploit_template: string | null;
  attack_scenario: string | null;
  evidence: Evidence[];
  file_paths: string[];
  created_at: string;
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
  ai_calls_made: number;
  scan_mode: string;
  obfuscated_files: number;
  is_monorepo: boolean;
  is_apk: boolean;
  doc_files_read: number;
  has_doc_intelligence: boolean;
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
  relevance: string;
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
