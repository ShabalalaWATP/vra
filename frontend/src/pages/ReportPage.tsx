import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Download,
  FileText,
  AlertTriangle,
  Key,
  Package,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  Info,
  FileCode2,
  Loader2,
  Eye,
  BookOpen,
  Crosshair,
  Lightbulb,
  BarChart3,
  Maximize2,
  Minimize2,
  ZoomIn,
  ZoomOut,
  Move,
  X,
  Shield,
  Layers,
  ListTree,
  ScanLine,
  MessageSquare,
  Search,
} from "lucide-react";
import { useState, useRef, useCallback, useEffect, Fragment } from "react";
import ReactMarkdown from "react-markdown";
import { api } from "@/api/client";
import ChatWindow from "@/components/ChatWindow";
import { MermaidDiagram } from "@/components/MermaidDiagram";
import { triggerBrowserDownload } from "@/utils/download";
import {
  SeverityDonut,
  ScannerHitsChart,
  FindingSourceChart,
  LanguageChart,
  CategoryChart,
  ConfidenceDistribution,
  DependencyRiskDonut,
  VerificationLevelChart,
} from "@/components/charts/Charts";
import type {
  Report,
  Finding,
  ExploitEvidence,
  RelatedAdvisory,
  SecretCandidate,
  DependencyFinding,
  DependencyUsageEvidence,
  OWASPEntry,
  ComponentScore,
  SBOMData,
  ScanCoverage,
  ScannerRunSummary,
} from "@/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS: Record<string, { bg: string; text: string; bar: string; hex: string }> = {
  critical: { bg: "bg-accent-danger/10", text: "text-accent-danger", bar: "bg-accent-danger", hex: "#ef4444" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", bar: "bg-orange-400", hex: "#fb923c" },
  medium: { bg: "bg-accent-warning/10", text: "text-accent-warning", bar: "bg-accent-warning", hex: "#f59e0b" },
  low: { bg: "bg-accent-success/10", text: "text-accent-success", bar: "bg-accent-success", hex: "#22c55e" },
  info: { bg: "bg-accent-primary/10", text: "text-accent-primary", bar: "bg-accent-primary", hex: "#38bdf8" },
};

function normalizeExploitEvidence(finding: Finding): ExploitEvidence | null {
  const payload = finding.exploit_evidence ?? {};
  const cleanList = (values?: string[] | null) =>
    Array.isArray(values) ? values.map((value) => String(value).trim()).filter(Boolean) : [];

  const evidence: ExploitEvidence = {
    difficulty: payload.difficulty || finding.exploit_difficulty || null,
    target_route: payload.target_route || null,
    prerequisites: cleanList(payload.prerequisites || finding.exploit_prerequisites),
    validation_steps: cleanList(payload.validation_steps),
    cleanup_notes: cleanList(payload.cleanup_notes),
    exploit_template: payload.exploit_template || finding.exploit_template || null,
    attack_scenario: payload.attack_scenario || finding.attack_scenario || null,
    components: cleanList(payload.components),
    related_entry_points: cleanList(payload.related_entry_points),
    related_taint_flows: cleanList(payload.related_taint_flows),
  };

  return Object.values(evidence).some((value) => {
    if (Array.isArray(value)) return value.length > 0;
    return Boolean(value);
  })
    ? evidence
    : null;
}

function normalizeFindingProvenance(value?: string | null): "scanner" | "llm" | "hybrid" {
  const normalized = String(value || "llm").trim().toLowerCase();
  if (normalized === "scanner") return "scanner";
  if (normalized === "hybrid") return "hybrid";
  return "llm";
}

function formatFindingProvenance(value?: string | null): string {
  const normalized = normalizeFindingProvenance(value);
  if (normalized === "scanner") return "Scanner-led";
  if (normalized === "hybrid") return "Hybrid";
  return "LLM-only";
}

function normalizeVerificationLevel(value?: string | null): string {
  const normalized = String(value || "hypothesis").trim().toLowerCase();
  if (normalized === "runtime_validated") return "runtime_validated";
  if (normalized === "strongly_verified") return "strongly_verified";
  if (normalized === "statically_verified") return "statically_verified";
  if (normalized === "dismissed") return "dismissed";
  return "hypothesis";
}

function formatVerificationLevel(value?: string | null): string {
  const normalized = normalizeVerificationLevel(value);
  if (normalized === "runtime_validated") return "Runtime";
  if (normalized === "strongly_verified") return "Strong";
  if (normalized === "statically_verified") return "Static";
  if (normalized === "dismissed") return "Dismissed";
  return "Hypothesis";
}

function getMergedFindingCount(finding: Finding): number {
  const raw = finding.merge_metadata?.merged_count;
  return typeof raw === "number" && raw > 1 ? raw : 1;
}

function diagramFamilyLabel(kind?: string): string | null {
  const normalized = String(kind || "").trim().toLowerCase();
  if (["overview", "security", "data_flow", "attack_surface"].includes(normalized)) {
    return "Architecture";
  }
  if (["result_overview", "trust_boundaries", "dependency_risk"].includes(normalized)) {
    return "Result-aware";
  }
  return null;
}

export default function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [exporting, setExporting] = useState<string | null>(null);
  const [currentFile, setCurrentFile] = useState<string>("");
  const [currentFileContent, setCurrentFileContent] = useState<string>("");
  const [chatPrompt, setChatPrompt] = useState<string>("");

  const { data: report, isLoading: reportLoading } = useQuery<Report>({
    queryKey: ["report", scanId],
    queryFn: () => api.get(`/scans/${scanId}/report`),
  });

  const { data: findings } = useQuery<Finding[]>({
    queryKey: ["findings", scanId],
    queryFn: () => api.get(`/scans/${scanId}/findings`),
  });

  const { data: secrets } = useQuery<SecretCandidate[]>({
    queryKey: ["secrets", scanId],
    queryFn: () => api.get(`/scans/${scanId}/secrets`),
  });

  const { data: depFindings } = useQuery<DependencyFinding[]>({
    queryKey: ["dep-findings", scanId],
    queryFn: () => api.get(`/scans/${scanId}/dependencies`),
  });

  const toggleFinding = (id: string) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedFindings = [...(findings || [])].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
  );
  const filteredFindings =
    severityFilter === "all"
      ? sortedFindings
      : sortedFindings.filter((f) => f.severity === severityFilter);

  const sevCounts: Record<string, number> = {};
  findings?.forEach((f) => {
    sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;
  });
  const categoryCounts: Record<string, number> = {};
  const findingSourceCounts: Record<string, number> = {
    scanner: 0,
    llm: 0,
    hybrid: 0,
  };
  const verificationCounts: Record<string, number> = {
    hypothesis: 0,
    statically_verified: 0,
    strongly_verified: 0,
    runtime_validated: 0,
  };
  let mergedDuplicateCount = 0;
  findings?.forEach((finding) => {
    const category = finding.category || "uncategorized";
    categoryCounts[category] = (categoryCounts[category] || 0) + 1;

    const provenance = normalizeFindingProvenance(finding.provenance);
    findingSourceCounts[provenance] = (findingSourceCounts[provenance] || 0) + 1;

    const verificationLevel = normalizeVerificationLevel(finding.verification_level);
    if (verificationLevel !== "dismissed") {
      verificationCounts[verificationLevel] = (verificationCounts[verificationLevel] || 0) + 1;
    }

    mergedDuplicateCount += Math.max(getMergedFindingCount(finding) - 1, 0);
  });

  const activeSecrets = secrets?.filter((s) => !s.is_false_positive) ?? [];
  const reachableDepCount = depFindings?.filter((d) => d.reachability_status === "reachable").length ?? 0;
  const activeDepCount =
    depFindings?.filter((d) => d.relevance === "used" || d.relevance === "likely_used").length ?? 0;
  const functionMatchedDepCount =
    depFindings?.filter((d) => (d.vulnerable_functions?.length ?? 0) > 0).length ?? 0;
  const highRiskDepCount = depFindings?.filter((d) => (d.risk_score ?? 0) >= 700).length ?? 0;

  const [exportError, setExportError] = useState<string | null>(null);

  const handleExport = async (format: "pdf" | "docx") => {
    setExporting(format);
    setExportError(null);
    try {
      const result = await api.post<{ id: string }>(
        `/scans/${scanId}/report/export`,
        { format }
      );
      triggerBrowserDownload(`/api/scans/${scanId}/report/export/${result.id}/download`);
    } catch (e: unknown) {
      setExportError(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(null);
    }
  };

  const techStack = report?.tech_stack as {
    languages?: string[];
    frameworks?: string[];
  } | null;
  const architectureData = parseArchitecturePayload(report?.architecture, report?.diagram_spec);
  const concreteAttackSurfacePoints = architectureData.attack_surface_points;
  const architectureEntryPoints = architectureData.entry_points;
  const architectureDataFlows = architectureData.data_flows;
  const exploitChainFindings = sortedFindings.filter(
    (finding) => String(finding.category || "").toLowerCase() === "exploit_chain"
  );
  const exploitableCount =
    findings?.filter((finding) => Boolean(normalizeExploitEvidence(finding))).length ?? 0;

  if (reportLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Loader2 className="w-8 h-8 text-accent-primary animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* ── Report Header ─────────────────────────────────────── */}
      <div className="relative overflow-hidden rounded-2xl border border-border">
        <div className="absolute inset-0 bg-gradient-to-br from-bg-card via-bg-tertiary to-bg-secondary" />
        <div className="absolute inset-0 bg-grid opacity-30" />
        <div
          className="absolute top-0 right-0 w-[400px] h-[400px] opacity-[0.05]"
          style={{ background: "radial-gradient(circle, #00d4ff 0%, transparent 70%)" }}
        />

        <div className="relative px-10 py-8">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-6">
              <img
                src="/logo.png"
                alt=""
                className="w-16 h-16 rounded-xl object-cover shadow-lg shadow-accent-primary/10"
              />
              <div>
                <h1 className="text-2xl font-bold">Security Assessment Report</h1>
                <p className="text-text-secondary text-sm mt-1">
                  {report?.created_at && new Date(report.created_at).toLocaleString()}
                </p>
                {/* Tech badges */}
                {techStack && (
                  <div className="flex gap-1.5 flex-wrap mt-3">
                    {techStack.languages?.map((l) => (
                      <TechBadge key={l} name={l} variant="language" />
                    ))}
                    {techStack.frameworks?.map((f) => (
                      <TechBadge key={f} name={f} variant="framework" />
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Export buttons */}
            <div className="flex gap-2 shrink-0">
              <button
                className="btn-secondary flex items-center gap-2"
                onClick={() => handleExport("pdf")}
                disabled={exporting !== null}
              >
                {exporting === "pdf" ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Download className="w-4 h-4" />
                )}
                PDF
              </button>
              <button
                className="btn-secondary flex items-center gap-2"
                onClick={() => handleExport("docx")}
                disabled={exporting !== null}
              >
                {exporting === "docx" ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <FileText className="w-4 h-4" />
                )}
                DOCX
              </button>
            </div>
            {exportError && (
              <p className="text-xs text-accent-danger mt-1">{exportError}</p>
            )}
          </div>

          {/* Severity summary strip */}
          {findings && findings.length > 0 && (
            <div className="flex items-center gap-6 mt-6 pt-6 border-t border-border/50">
              <span className="text-sm text-text-muted">Findings:</span>
              {SEVERITY_ORDER.map((sev) => {
                const count = sevCounts[sev] || 0;
                if (count === 0) return null;
                const c = SEVERITY_COLORS[sev];
                return (
                  <div key={sev} className="flex items-center gap-2">
                    <div className={`hex-dot-${sev}`} />
                    <span className={`text-sm font-semibold ${c.text}`}>{count}</span>
                    <span className="text-xs text-text-muted capitalize">{sev}</span>
                  </div>
                );
              })}
              <div className="ml-auto flex items-center gap-2 text-text-muted text-sm">
                <span className="font-semibold text-text-primary">{findings.length}</span>
                total
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Executive Risk Score ─────────────────────────────── */}
      {report?.risk_grade && (
        <RiskScoreBanner
          grade={report.risk_grade}
          score={report.risk_score ?? 0}
          findingCount={findings?.length ?? 0}
          criticalCount={sevCounts["critical"] || 0}
          highCount={sevCounts["high"] || 0}
        />
      )}

      {/* ── App Summary + Codebase Statistics ─────────────────── */}
      <div className="grid grid-cols-3 gap-6">
        {/* App Summary — 2 cols */}
        <section className="col-span-2 card-glow border-gradient">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-lg bg-accent-primary/10 flex items-center justify-center">
              <Eye className="w-4 h-4 text-accent-primary" />
            </div>
            <h2 className="text-lg font-semibold">Application Summary</h2>
          </div>
          {report?.app_summary ? (
            <div className="space-y-4">
              <div className="prose prose-invert prose-sm max-w-none text-text-secondary
                prose-headings:text-text-primary prose-headings:font-semibold prose-headings:mt-4 prose-headings:mb-2
                prose-h3:text-base prose-h4:text-sm
                prose-p:leading-relaxed prose-p:mb-3
                prose-ul:my-2 prose-li:my-0.5
                prose-strong:text-text-primary
                prose-code:text-accent-primary prose-code:bg-bg-secondary prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-xs
                prose-a:text-accent-primary">
                <ReactMarkdown>{report.app_summary}</ReactMarkdown>
              </div>

              {/* Concrete Attack Paths */}
              {concreteAttackSurfacePoints.length > 0 ? (
                <div className="mt-4 pt-4 border-t border-border/30">
                  <div className="flex items-center justify-between gap-3 mb-3">
                    <h3 className="text-sm font-semibold text-text-primary">Exposed Attack Paths</h3>
                    <span className="text-[10px] font-mono text-text-muted">
                      {concreteAttackSurfacePoints.length} mapped
                    </span>
                  </div>
                  <div className="space-y-2">
                    {concreteAttackSurfacePoints.slice(0, 4).map((point) => (
                      <div
                        key={point}
                        className="rounded-lg border border-accent-danger/15 bg-accent-danger/5 px-3 py-2 text-xs font-mono text-text-secondary"
                      >
                        {point}
                      </div>
                    ))}
                    {concreteAttackSurfacePoints.length > 4 && (
                      <p className="text-[11px] text-text-muted">
                        +{concreteAttackSurfacePoints.length - 4} additional mapped routes, handlers, or exposed functions.
                      </p>
                    )}
                  </div>
                </div>
              ) : report.attack_surface && Object.keys(report.attack_surface).length > 0 ? (
                <div className="mt-4 pt-4 border-t border-border/30">
                  <h3 className="text-sm font-semibold text-text-primary mb-2">Finding Surface Mix</h3>
                  <p className="text-xs text-text-muted mb-3">
                    These counts are derived from findings and scanner coverage, not concrete routes or handlers.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(report.attack_surface as Record<string, number>)
                      .sort((a, b) => (b[1] as number) - (a[1] as number))
                      .map(([key, val]) => (
                        <span
                          key={key}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-bg-secondary px-2.5 py-1 text-xs font-medium text-text-muted"
                        >
                          {key}
                          <span className="font-mono text-[10px] opacity-70">{String(val)}</span>
                        </span>
                      ))}
                  </div>
                </div>
              ) : null}

              {/* Key Architecture Notes */}
              {report.architecture && (
                <details className="mt-2 group">
                  <summary className="flex items-center gap-2 cursor-pointer text-sm font-semibold text-text-primary hover:text-accent-primary transition-colors select-none">
                    <ChevronDown className="w-4 h-4 transition-transform group-open:rotate-0 -rotate-90" />
                    Architecture Analysis
                  </summary>
                  <div className="mt-3 pl-6 max-h-[500px] overflow-y-auto">
                    <ArchitectureAnalysisPanel data={architectureData} rawArchitecture={report.architecture} />
                  </div>
                </details>
              )}
            </div>
          ) : (
            <p className="text-text-muted text-sm">No summary available.</p>
          )}
        </section>

        {/* Codebase Statistics — 1 col */}
        <section className="card-glow border-gradient">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-lg bg-accent-secondary/10 flex items-center justify-center">
              <BarChart3 className="w-4 h-4 text-accent-secondary" />
            </div>
            <h2 className="text-lg font-semibold">Codebase</h2>
          </div>
          <CodebaseStats techStack={techStack} fingerprint={(techStack as any)?.fingerprint} />
        </section>
      </div>

      {/* ── Architecture Diagrams ──────────────────────────────── */}
      {(((report?.diagram_count ?? 0) > 0) || architectureData.diagrams.length > 0 || report?.diagram_spec) && (
        <DiagramViewer
          scanId={scanId!}
          architectureData={architectureData}
          hasDiagramImage={report?.has_diagram_image ?? false}
          diagramCount={report?.diagram_count ?? 0}
        />
      )}

      {/* ── Codebase Browser ────────────────────────────────── */}
      <CodeBrowser
        scanId={scanId!}
        onFileSelect={(path, content) => {
          setCurrentFile(path);
          setCurrentFileContent(content);
        }}
        findings={findings}
        onAskAboutFile={(prompt) => setChatPrompt(prompt)}
      />

      {/* ── Scan Statistics ──────────────────────────────────── */}
      {(() => {
        const advisoryCount = findings?.filter((f) => f.related_cves && f.related_cves.length > 0).length ?? 0;
        const critHighCount = (sevCounts["critical"] || 0) + (sevCounts["high"] || 0);
        return (
          <section className="grid grid-cols-2 md:grid-cols-6 gap-4">
            {[
              { label: "Total Findings", value: findings?.length ?? 0, color: "text-accent-warning" },
              { label: "Critical / High", value: critHighCount, color: critHighCount > 0 ? "text-accent-danger" : "text-accent-success" },
              { label: "Exploitable (PoC)", value: exploitableCount, color: exploitableCount > 0 ? "text-accent-danger" : "text-text-muted" },
              { label: "Advisory Correlated", value: advisoryCount, color: advisoryCount > 0 ? "text-orange-400" : "text-text-muted" },
              { label: "Dep. Risks", value: depFindings?.length ?? 0, color: (depFindings?.length ?? 0) > 0 ? "text-accent-warning" : "text-text-muted" },
              { label: "Merged Dups", value: mergedDuplicateCount, color: mergedDuplicateCount > 0 ? "text-accent-primary" : "text-text-muted" },
            ].map((stat) => (
              <div key={stat.label} className="card-glow text-center py-4">
                <p className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</p>
                <p className="text-xs text-text-muted mt-1">{stat.label}</p>
              </div>
            ))}
          </section>
        );
      })()}

      {/* ── Visual Analytics Dashboard ─────────────────────── */}
      <section className="card-glow border-gradient">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-8 h-8 rounded-lg bg-accent-primary/10 flex items-center justify-center">
            <BarChart3 className="w-4 h-4 text-accent-primary" />
          </div>
          <h2 className="text-lg font-semibold">Scan Analytics</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
          {/* Severity donut */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 flex items-center justify-center min-h-[300px]">
            {findings && findings.length > 0 ? (
              <SeverityDonut counts={sevCounts} size={260} />
            ) : (
              <p className="text-text-muted text-sm">No findings</p>
            )}
          </div>

          {/* Confidence distribution */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 flex items-center justify-center min-h-[300px]">
            {findings && findings.length > 0 ? (
              <ConfidenceDistribution findings={findings} size={260} />
            ) : (
              <p className="text-text-muted text-sm">No findings</p>
            )}
          </div>

          {/* Scanner hits */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 min-h-[300px]">
            {report?.scanner_hits ? (
              <ScannerHitsChart hitCounts={report.scanner_hits as Record<string, number>} />
            ) : (
              <p className="text-text-muted text-sm">No scanner data</p>
            )}
          </div>

          {/* Final finding sources */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 min-h-[300px]">
            {findings && findings.length > 0 ? (
              <FindingSourceChart counts={findingSourceCounts} />
            ) : (
              <p className="text-text-muted text-sm">No findings</p>
            )}
          </div>

          {/* Verification levels */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 min-h-[300px]">
            {findings && findings.length > 0 ? (
              <VerificationLevelChart counts={verificationCounts} />
            ) : (
              <p className="text-text-muted text-sm">No findings</p>
            )}
          </div>

          {/* Finding categories */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 min-h-[300px]">
            {findings && findings.length > 0 ? (
              <CategoryChart categories={categoryCounts} />
            ) : (
              <p className="text-text-muted text-sm">No findings</p>
            )}
          </div>
        </div>

        {/* Second row: attack paths + languages + dependency risks */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-8 pt-6 border-t border-border/30">
          {/* Concrete attack paths */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 min-h-[280px]">
            <AttackPathPanel
              attackSurfacePoints={concreteAttackSurfacePoints}
              entryPoints={architectureEntryPoints}
              dataFlows={architectureDataFlows}
              fallbackMetrics={report?.attack_surface as Record<string, number> | null | undefined}
            />
          </div>

          {/* Language distribution */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 flex items-center justify-center min-h-[280px]">
            {(() => {
              const fp = (techStack as any)?.fingerprint;
              const langs = fp?.languages as Array<{ name: string; file_count: number }> | undefined;
              if (!langs?.length) return <p className="text-text-muted text-sm">No language data</p>;
              return <LanguageChart languages={langs} size={260} />;
            })()}
          </div>

          {/* Dependency risk donut */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 flex items-center justify-center min-h-[280px]">
            {depFindings && depFindings.length > 0 ? (
              <DependencyRiskDonut depFindings={depFindings!} size={260} />
            ) : (
              <p className="text-text-muted text-sm">No dependency data</p>
            )}
          </div>
        </div>
      </section>

      {/* ── Written Security Review ────────────────────────────── */}
      <section className="card-glow border-gradient">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-8 h-8 rounded-lg bg-accent-secondary/10 flex items-center justify-center">
            <BookOpen className="w-4 h-4 text-accent-secondary" />
          </div>
          <h2 className="text-lg font-semibold">Security Review</h2>
        </div>
        <div className="prose prose-invert prose-sm max-w-none space-y-4 text-text-secondary leading-relaxed">
          {report?.narrative ? (
            report.narrative.split("\n\n").map((p: string, i: number) => (
              <p key={i}>{p}</p>
            ))
          ) : findings && findings.length > 0 ? (
            (() => {
              const cats = findings.reduce((acc, f) => {
                const cat = f.category || "other";
                acc[cat] = (acc[cat] || 0) + 1;
                return acc;
              }, {} as Record<string, number>);
              const topCats = Object.entries(cats)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5);
              const exploitable = findings.filter((f) => f.exploit_difficulty === "easy" || f.exploit_difficulty === "moderate");
              const withAdvisories = findings.filter((f) => f.related_cves && f.related_cves.length > 0);

              return (
                <>
                  <h3 className="text-base font-semibold text-text-primary mt-2">Executive Summary</h3>
                  <p>
                    This security assessment identified <strong className="text-text-primary">{findings.length} security findings</strong> across
                    the target application. The severity breakdown comprises{" "}
                    <strong className="text-accent-danger">{sevCounts.critical || 0} critical</strong>,{" "}
                    <strong className="text-orange-400">{sevCounts.high || 0} high</strong>,{" "}
                    <strong className="text-accent-warning">{sevCounts.medium || 0} medium</strong>,{" "}
                    <strong className="text-accent-success">{sevCounts.low || 0} low</strong>, and{" "}
                    <strong className="text-accent-primary">{sevCounts.info || 0} informational</strong> severity issues.
                    {(sevCounts.critical || 0) + (sevCounts.high || 0) > 5
                      ? " The volume of critical and high severity findings indicates significant security weaknesses that require immediate remediation before production deployment."
                      : (sevCounts.critical || 0) + (sevCounts.high || 0) > 0
                      ? " Several high-priority issues require prompt attention to reduce risk exposure."
                      : " No critical issues were identified, though lower-severity findings should still be addressed as part of defense-in-depth."}
                  </p>

                  <h3 className="text-base font-semibold text-text-primary mt-4">Key Risk Areas</h3>
                  <p>The most prevalent vulnerability categories identified are:</p>
                  <ul className="list-disc list-inside space-y-1 ml-2">
                    {topCats.map(([cat, count]) => (
                      <li key={cat}>
                        <strong className="text-text-primary">{cat.replace(/_/g, " ")}</strong>{" "}
                        — {count} finding{count !== 1 ? "s" : ""}
                      </li>
                    ))}
                  </ul>

                  {exploitable.length > 0 && (
                    <>
                      <h3 className="text-base font-semibold text-text-primary mt-4">Exploitability Assessment</h3>
                      <p>
                        Of the confirmed findings, <strong className="text-accent-danger">{exploitable.length} findings</strong> were
                        assessed as having easy or moderate exploit difficulty, meaning an attacker with basic knowledge
                        could potentially leverage these vulnerabilities. Proof-of-concept exploit templates have been
                        generated for findings where exploitation was demonstrated to be feasible.
                      </p>
                    </>
                  )}

                  {withAdvisories.length > 0 && (
                    <p>
                      <strong className="text-text-primary">{withAdvisories.length} findings</strong> were correlated with known
                      advisories in the offline vulnerability database, indicating that similar vulnerability patterns have been publicly
                      documented and may have known exploit techniques.
                    </p>
                  )}

                  <h3 className="text-base font-semibold text-text-primary mt-4">Methodology</h3>
                  <p>
                    The analysis was performed using a multi-pass approach combining automated static analysis scanners
                    (Semgrep, Bandit, ESLint, CodeQL, secrets detection, dependency audit) with AI-powered code investigation.
                    The AI investigator inspected {report?.scan_coverage?.files_inspected_by_ai || "multiple"} source files,
                    tracing input validation paths, authentication boundaries, and data serialization flows from
                    user-controlled input sources to dangerous sinks (database queries, OS commands, file operations, HTML output).
                  </p>
                  <p>
                    Each finding was independently verified by an AI verification agent that assessed evidence both
                    supporting and opposing the vulnerability hypothesis. Findings below the confidence threshold were
                    automatically dismissed to reduce false positives.
                  </p>

                  <h3 className="text-base font-semibold text-text-primary mt-4">Recommendations</h3>
                  <p>
                    {(sevCounts.critical || 0) > 0
                      ? "Immediate action is required to address all critical severity findings. These represent exploitable vulnerabilities that could lead to full system compromise, data exfiltration, or unauthorized access."
                      : (sevCounts.high || 0) > 0
                      ? "High severity findings should be prioritized for remediation in the next development sprint. These represent significant risk to the application's security posture."
                      : "Lower severity findings should be addressed as part of ongoing security hardening. While individually less impactful, they may be chained together for more significant attacks."
                    }
                    {" "}Detailed remediation guidance is provided for each finding in the Security Findings section below.
                  </p>
                </>
              );
            })()
          ) : (
            <p>No security findings were identified during this scan.</p>
          )}
        </div>
      </section>

      {/* ── Exploit Chains ────────────────────────────────────── */}
      {exploitChainFindings.length > 0 && (
        <ExploitChainsSection findings={exploitChainFindings} />
      )}

      {/* ── Security Findings ─────────────────────────────────── */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-accent-warning/10 flex items-center justify-center">
              <AlertTriangle className="w-4 h-4 text-accent-warning" />
            </div>
            <h2 className="text-lg font-semibold">
              Security Findings
              <span className="text-text-muted font-normal ml-2 text-base">
                ({findings?.length ?? 0})
              </span>
            </h2>
          </div>

          {/* Severity filter */}
          <div className="flex gap-1">
            {["all", ...SEVERITY_ORDER].map((sev) => {
              const count = sev === "all" ? findings?.length : sevCounts[sev] || 0;
              return (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`text-xs px-3 py-1.5 rounded-lg transition-all ${
                    severityFilter === sev
                      ? "bg-accent-primary text-bg-primary font-medium"
                      : "bg-bg-tertiary text-text-muted hover:text-text-primary hover:bg-bg-hover"
                  }`}
                >
                  {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
                  {count ? ` (${count})` : ""}
                </button>
              );
            })}
          </div>
        </div>

        {/* Findings list */}
        {filteredFindings?.length ? (
          <div className="space-y-3">
            {filteredFindings.map((f, idx) => {
              const isExpanded = expandedFindings.has(f.id);
              const sc = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info;
              const exploitEvidence = normalizeExploitEvidence(f);
              const exploitDifficulty = exploitEvidence?.difficulty || null;
              const provenance = normalizeFindingProvenance(f.provenance);
              const verificationLevel = normalizeVerificationLevel(f.verification_level);
              const mergedCount = getMergedFindingCount(f);
              const provenanceBadgeClass =
                provenance === "scanner"
                  ? "bg-accent-primary/10 text-accent-primary"
                  : provenance === "hybrid"
                  ? "bg-accent-secondary/10 text-accent-secondary"
                  : "bg-accent-warning/10 text-accent-warning";
              const verificationBadgeClass =
                verificationLevel === "runtime_validated"
                  ? "bg-accent-danger/10 text-accent-danger"
                  : verificationLevel === "strongly_verified"
                  ? "bg-accent-success/10 text-accent-success"
                  : verificationLevel === "statically_verified"
                  ? "bg-accent-primary/10 text-accent-primary"
                  : "bg-bg-secondary text-text-muted";

              return (
                <div
                  key={f.id}
                  className={`card-glow overflow-hidden border-l-[3px] ${
                    isExpanded ? "border-l-accent-primary" : `border-l-transparent`
                  }`}
                  style={{
                    borderLeftColor: isExpanded ? undefined : sc.hex,
                  }}
                >
                  {/* Header */}
                  <button
                    className="w-full flex items-center gap-4 text-left group"
                    onClick={() => toggleFinding(f.id)}
                  >
                    <span className="text-text-muted text-sm w-6 text-right shrink-0">
                      {idx + 1}.
                    </span>
                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-text-muted shrink-0" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-text-muted shrink-0 group-hover:text-text-secondary" />
                    )}
                    <span className={`badge badge-${f.severity} shrink-0`}>
                      {f.severity.toUpperCase()}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-medium shrink-0 ${provenanceBadgeClass}`}>
                      {formatFindingProvenance(f.provenance)}
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-medium shrink-0 ${verificationBadgeClass}`}>
                      {formatVerificationLevel(f.verification_level)}
                    </span>
                    <span className="font-medium flex-1 group-hover:text-accent-primary transition-colors">
                      {f.title}
                    </span>
                    {f.category && (
                      <span className="text-[10px] text-text-muted bg-bg-secondary px-2 py-0.5 rounded font-mono shrink-0">
                        {f.category}
                      </span>
                    )}
                    {f.cwe_ids && f.cwe_ids.length > 0 && (
                      <div className="flex gap-1 shrink-0">
                        {f.cwe_ids.slice(0, 2).map((cwe) => (
                          <span
                            key={cwe}
                            className="text-[9px] text-accent-secondary bg-accent-secondary/10 px-1.5 py-0.5 rounded font-mono shrink-0"
                          >
                            {cwe}
                          </span>
                        ))}
                      </div>
                    )}
                    {mergedCount > 1 && (
                      <span className="text-[9px] text-text-secondary bg-bg-secondary px-1.5 py-0.5 rounded font-mono shrink-0">
                        merged x{mergedCount}
                      </span>
                    )}
                    <ConfidenceBar value={f.confidence} />
                  </button>

                  {/* Expanded detail */}
                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t border-border/50 space-y-5">
                      {/* Description */}
                      <p className="text-sm text-text-secondary leading-relaxed pl-10">
                        {f.description}
                      </p>

                      {(f.provenance || f.verification_level || (f.source_scanners?.length ?? 0) > 0 || (f.source_rules?.length ?? 0) > 0 || f.verification_notes || mergedCount > 1) && (
                        <div className="pl-10">
                          <div className="rounded-xl border border-border bg-bg-secondary/50 p-4">
                            <div className="flex items-center gap-2 mb-3">
                              <Shield className="w-4 h-4 text-accent-primary" />
                              <span className="text-xs font-semibold text-text-primary uppercase tracking-wider">
                                Assessment
                              </span>
                            </div>
                            <div className="flex flex-wrap gap-2 mb-3">
                              <span className={`text-[10px] px-2 py-0.5 rounded font-medium ${provenanceBadgeClass}`}>
                                {formatFindingProvenance(f.provenance)}
                              </span>
                              <span className={`text-[10px] px-2 py-0.5 rounded font-medium ${verificationBadgeClass}`}>
                                {formatVerificationLevel(f.verification_level)}
                              </span>
                              {mergedCount > 1 && (
                                <span className="text-[10px] px-2 py-0.5 rounded bg-bg-tertiary text-text-secondary font-medium">
                                  {mergedCount} merged candidates
                                </span>
                              )}
                            </div>
                            {f.source_scanners && f.source_scanners.length > 0 && (
                              <p className="text-xs text-text-secondary leading-relaxed">
                                <span className="text-text-muted">Source scanners: </span>
                                {f.source_scanners.join(", ")}
                              </p>
                            )}
                            {f.source_rules && f.source_rules.length > 0 && (
                              <p className="text-xs text-text-secondary leading-relaxed mt-1">
                                <span className="text-text-muted">Source rules: </span>
                                {f.source_rules.slice(0, 6).join(", ")}
                              </p>
                            )}
                            {f.verification_notes && (
                              <p className="text-xs text-text-secondary leading-relaxed mt-2">
                                <span className="text-text-muted">Verification notes: </span>
                                {f.verification_notes}
                              </p>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Related advisories */}
                      {f.related_cves && f.related_cves.length > 0 && (
                        <div className="pl-10 space-y-1.5">
                          <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium">Related Advisories</p>
                          {f.related_cves.map((advisory, idx) => {
                            const advisoryId =
                              advisory.display_id || advisory.cve_id || advisory.advisory_id || `advisory-${idx + 1}`;
                            return (
                              <div key={`${advisoryId}-${idx}`} className="text-xs bg-accent-danger/5 border border-accent-danger/10 rounded-lg px-3 py-2">
                                <div className="flex items-start gap-3">
                                  <span className="font-mono text-accent-danger font-medium shrink-0">{advisoryId}</span>
                                  <div className="min-w-0 flex-1">
                                    <div className="flex flex-wrap items-center gap-1.5 mb-1.5">
                                      <span className={`badge badge-${String(advisory.severity || "medium").toLowerCase()} text-[9px]`}>
                                        {String(advisory.severity || "medium").toUpperCase()}
                                      </span>
                                      {advisory.evidence_strength && (
                                        <AdvisoryStrengthBadge strength={advisory.evidence_strength} />
                                      )}
                                      {advisory.evidence_type && (
                                        <AdvisoryEvidenceBadge evidenceType={advisory.evidence_type} />
                                      )}
                                      {typeof advisory.package_match_confidence === "number" && (
                                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-accent-primary/10 text-accent-primary font-medium">
                                          {Math.round(advisory.package_match_confidence * 100)}% package match
                                        </span>
                                      )}
                                    </div>
                                    <p className="text-text-secondary leading-relaxed">{advisory.summary}</p>
                                    <div className="mt-2 flex flex-wrap gap-1.5">
                                      {advisory.package && (
                                        <span className="text-[10px] text-text-muted bg-bg-secondary px-1.5 py-0.5 rounded">
                                          {advisory.package}
                                          {advisory.ecosystem ? ` • ${advisory.ecosystem}` : ""}
                                        </span>
                                      )}
                                      {advisory.import_module && (
                                        <span className="text-[10px] text-text-muted bg-bg-secondary px-1.5 py-0.5 rounded">
                                          import {advisory.import_module}
                                        </span>
                                      )}
                                      {formatAdvisoryFunctionLabel(advisory) && (
                                        <span className="text-[10px] text-text-muted bg-bg-secondary px-1.5 py-0.5 rounded">
                                          {formatAdvisoryFunctionLabel(advisory)}
                                        </span>
                                      )}
                                      {advisory.fixed_version && (
                                        <span className="text-[10px] text-text-muted bg-bg-secondary px-1.5 py-0.5 rounded">
                                          fix {advisory.fixed_version}
                                        </span>
                                      )}
                                    </div>
                                    {(advisory.evidence_sources?.length || advisory.cwe_ids?.length) && (
                                      <div className="mt-2 flex flex-wrap gap-1.5">
                                        {advisory.evidence_sources?.slice(0, 2).map((source) => (
                                          <span
                                            key={`${advisoryId}-${source}`}
                                            className="text-[10px] text-accent-secondary bg-accent-secondary/10 px-1.5 py-0.5 rounded"
                                          >
                                            {formatDependencyLabel(source)}
                                          </span>
                                        ))}
                                        {advisory.cwe_ids?.slice(0, 2).map((cwe) => (
                                          <span
                                            key={`${advisoryId}-${cwe}`}
                                            className="text-[10px] text-accent-secondary bg-accent-secondary/10 px-1.5 py-0.5 rounded font-mono"
                                          >
                                            {cwe}
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {/* Affected files */}
                      {f.file_paths.length > 0 && (
                        <div className="flex gap-2 flex-wrap pl-10">
                          {f.file_paths.map((fp) => (
                            <span
                              key={fp}
                              className="inline-flex items-center gap-1.5 text-xs font-mono bg-bg-secondary px-2.5 py-1 rounded-lg text-text-secondary"
                            >
                              <FileCode2 className="w-3 h-3 text-text-muted" />
                              {fp}
                            </span>
                          ))}
                        </div>
                      )}

                      {/* Code snippet */}
                      {f.code_snippet && (
                        <div className="pl-10">
                          <div className="rounded-xl overflow-hidden border border-border">
                            <div className="bg-bg-tertiary px-4 py-2 border-b border-border flex items-center gap-2">
                              <FileCode2 className="w-3.5 h-3.5 text-text-muted" />
                              <span className="text-xs text-text-muted">Vulnerable Code</span>
                            </div>
                            <pre className="bg-bg-secondary px-4 py-3 text-xs font-mono overflow-x-auto leading-relaxed text-text-primary">
                              {f.code_snippet}
                            </pre>
                          </div>
                        </div>
                      )}

                      {/* Explanation */}
                      {f.explanation && (
                        <DetailBlock
                          icon={<Crosshair className="w-4 h-4" />}
                          title="Explanation"
                          color="text-accent-primary"
                        >
                          {f.explanation}
                        </DetailBlock>
                      )}

                      {/* Impact */}
                      {f.impact && (
                        <DetailBlock
                          icon={<AlertTriangle className="w-4 h-4" />}
                          title="Impact"
                          color="text-accent-warning"
                        >
                          {f.impact}
                        </DetailBlock>
                      )}

                      {/* Remediation */}
                      {f.remediation && (
                        <div className="pl-10">
                          <div className="rounded-xl bg-accent-success/5 border border-accent-success/20 p-4">
                            <div className="flex items-center gap-2 mb-2">
                              <Lightbulb className="w-4 h-4 text-accent-success" />
                              <span className="text-xs font-semibold text-accent-success uppercase tracking-wider">
                                Remediation
                              </span>
                            </div>
                            <p className="text-sm text-text-primary leading-relaxed">
                              {f.remediation}
                            </p>
                          </div>
                        </div>
                      )}

                      {/* Exploit Assessment */}
                      {exploitEvidence && (
                        <div className="pl-10">
                          <div className={`rounded-xl p-4 border ${
                            exploitDifficulty === "easy"
                              ? "bg-accent-danger/5 border-accent-danger/20"
                              : exploitDifficulty === "moderate"
                              ? "bg-accent-warning/5 border-accent-warning/20"
                              : "bg-bg-secondary/50 border-border"
                          }`}>
                            <div className="flex items-center gap-3 mb-2">
                              <Crosshair className={`w-4 h-4 ${
                                exploitDifficulty === "easy" ? "text-accent-danger" :
                                exploitDifficulty === "moderate" ? "text-accent-warning" :
                                "text-text-muted"
                              }`} />
                              <span className="text-xs font-semibold uppercase tracking-wider">
                                {exploitDifficulty ? `Exploit Difficulty: ${exploitDifficulty}` : "Exploit Evidence"}
                              </span>
                            </div>
                            {exploitEvidence.target_route && (
                              <p className="text-sm text-text-primary leading-relaxed mb-2">
                                <span className="text-text-muted">Target route / invocation: </span>
                                <span className="font-mono text-xs">{exploitEvidence.target_route}</span>
                              </p>
                            )}
                            {exploitEvidence.attack_scenario && (
                              <p className="text-sm text-text-secondary leading-relaxed mb-3">
                                {exploitEvidence.attack_scenario}
                              </p>
                            )}
                            {exploitEvidence.prerequisites && exploitEvidence.prerequisites.length > 0 && (
                              <div className="mb-3">
                                <span className="text-xs text-text-muted">Prerequisites: </span>
                                <span className="text-xs text-text-secondary">
                                  {exploitEvidence.prerequisites.join(", ")}
                                </span>
                              </div>
                            )}
                            {exploitEvidence.components && exploitEvidence.components.length > 0 && (
                              <div className="mb-3">
                                <span className="text-xs text-text-muted">Components: </span>
                                <span className="text-xs text-text-secondary">
                                  {exploitEvidence.components.join(", ")}
                                </span>
                              </div>
                            )}
                            {exploitEvidence.related_entry_points && exploitEvidence.related_entry_points.length > 0 && (
                              <div className="mb-3">
                                <span className="text-xs text-text-muted">Related entry points:</span>
                                <div className="mt-1 flex flex-wrap gap-1.5">
                                  {exploitEvidence.related_entry_points.map((entryPoint) => (
                                    <span
                                      key={`${f.id}-entry-${entryPoint}`}
                                      className="rounded bg-bg-secondary px-2 py-1 text-[11px] font-mono text-text-secondary"
                                    >
                                      {entryPoint}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}
                            {exploitEvidence.related_taint_flows && exploitEvidence.related_taint_flows.length > 0 && (
                              <div className="mb-3">
                                <span className="text-xs text-text-muted">Related taint flows:</span>
                                <div className="mt-1 space-y-1">
                                  {exploitEvidence.related_taint_flows.map((flow) => (
                                    <div
                                      key={`${f.id}-flow-${flow}`}
                                      className="rounded bg-bg-secondary px-2 py-1 text-[11px] text-text-secondary"
                                    >
                                      {flow}
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}
                            {exploitEvidence.validation_steps && exploitEvidence.validation_steps.length > 0 && (
                              <div className="mb-3">
                                <span className="text-xs text-text-muted">Validation steps:</span>
                                <ul className="mt-1 space-y-1 text-xs text-text-secondary list-disc list-inside">
                                  {exploitEvidence.validation_steps.map((step) => (
                                    <li key={`${f.id}-validation-${step}`}>{step}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {exploitEvidence.cleanup_notes && exploitEvidence.cleanup_notes.length > 0 && (
                              <div className="mb-3">
                                <span className="text-xs text-text-muted">Cleanup notes:</span>
                                <ul className="mt-1 space-y-1 text-xs text-text-secondary list-disc list-inside">
                                  {exploitEvidence.cleanup_notes.map((step) => (
                                    <li key={`${f.id}-cleanup-${step}`}>{step}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {exploitEvidence.exploit_template && (
                              <div className="rounded-lg overflow-hidden border border-border mt-2">
                                <div className="bg-bg-tertiary px-3 py-1.5 border-b border-border">
                                  <span className="text-[10px] text-text-muted uppercase tracking-wider font-medium">
                                    Proof of Concept
                                  </span>
                                </div>
                                <pre className="bg-bg-secondary px-3 py-2 text-xs font-mono overflow-x-auto text-accent-danger/80">
                                  {exploitEvidence.exploit_template}
                                </pre>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Evidence */}
                      {f.evidence.length > 0 && (
                        <div className="pl-10">
                          <h4 className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
                            Evidence
                          </h4>
                          <div className="space-y-1.5">
                            {f.evidence.map((ev) => (
                              <div
                                key={ev.id}
                                className={`flex items-start gap-2 text-xs ${
                                  ev.type === "supporting"
                                    ? "text-accent-danger"
                                    : ev.type === "opposing"
                                    ? "text-accent-success"
                                    : "text-text-secondary"
                                }`}
                              >
                                <span className="shrink-0 mt-0.5 font-mono font-bold">
                                  {ev.type === "supporting" ? "+" : ev.type === "opposing" ? "−" : "~"}
                                </span>
                                <span>{ev.description}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Ask AI about this finding */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setChatPrompt(
                            `Explain this finding in detail and suggest how to fix it:\n\n` +
                            `**${f.title}** [${f.severity.toUpperCase()}]\n` +
                            `Category: ${f.category || "unknown"}\n` +
                            `File: ${f.file_paths?.[0] || "unknown"}\n` +
                            (f.description ? `Description: ${f.description}\n` : "") +
                            (f.code_snippet ? `Code:\n\`\`\`\n${f.code_snippet}\n\`\`\`\n` : "")
                          );
                        }}
                        className="flex items-center gap-2 px-3 py-2 rounded-lg bg-accent-primary/10 text-accent-primary text-xs font-medium
                          hover:bg-accent-primary/20 transition-colors mt-2"
                      >
                        <MessageSquare className="w-3.5 h-3.5" />
                        Ask AI about this finding
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="card-glow text-center py-12">
            <CheckCircle2 className="w-10 h-10 text-accent-success mx-auto mb-3 opacity-50" />
            <p className="text-text-muted text-sm">
              {severityFilter === "all"
                ? "No security findings were identified."
                : `No ${severityFilter} severity findings.`}
            </p>
          </div>
        )}
      </section>

      {/* ── Secrets ───────────────────────────────────────────── */}
      {activeSecrets.length > 0 && (
        <SecretsSection secrets={activeSecrets} />
      )}

      {/* ── Dependencies ──────────────────────────────────────── */}
      {depFindings && depFindings.length > 0 && (
        <section className="card-glow border-gradient">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-lg bg-accent-warning/10 flex items-center justify-center">
              <Package className="w-4 h-4 text-accent-warning" />
            </div>
            <h2 className="text-lg font-semibold">
              Dependency Risks
              <span className="text-text-muted font-normal ml-2 text-base">
                ({depFindings.length})
              </span>
            </h2>
          </div>
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 mb-5">
            {[
              { label: "Reachable", value: reachableDepCount, tone: "text-accent-danger" },
              { label: "Imported / likely used", value: activeDepCount, tone: "text-accent-warning" },
              { label: "Function matches", value: functionMatchedDepCount, tone: "text-accent-primary" },
              { label: "700+ risk score", value: highRiskDepCount, tone: "text-orange-400" },
            ].map((stat) => (
              <div key={stat.label} className="rounded-xl border border-border/40 bg-bg-secondary/40 px-4 py-3">
                <p className={`text-lg font-bold font-mono ${stat.tone}`}>{stat.value}</p>
                <p className="text-[10px] uppercase tracking-wider text-text-muted mt-1">{stat.label}</p>
              </div>
            ))}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Package</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Advisory</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Exposure</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Risk</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Assessment</th>
                </tr>
              </thead>
              <tbody>
                {depFindings.map((d) => {
                  const usageHits = d.usage_evidence?.slice(0, 3) ?? [];
                  const remainingUsageHits = Math.max(0, (d.usage_evidence?.length ?? 0) - usageHits.length);
                  const riskFactors = formatDependencyRiskFactors(d.risk_factors);

                  return (
                  <tr key={d.id} className="border-b border-border/30 hover:bg-bg-hover/20">
                    <td className="py-3 align-top">
                      <div className="font-mono text-xs font-medium">{d.package_name}</div>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        <span className="text-[10px] uppercase tracking-wide text-text-muted">
                          {d.ecosystem}
                        </span>
                        <span className="text-[10px] font-mono text-text-secondary">
                          Installed {d.installed_version || "unknown"}
                        </span>
                        {d.fixed_version && (
                          <span className="text-[10px] font-mono text-accent-success">
                            Fix {d.fixed_version}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 align-top text-xs">
                      <div className="font-mono text-text-secondary">{d.advisory_id || "Offline advisory"}</div>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {d.severity && (
                          <span className={`badge badge-${d.severity}`}>
                            {d.severity.toUpperCase()}
                          </span>
                        )}
                        {typeof d.cvss_score === "number" && (
                          <span className="text-[10px] px-2 py-0.5 rounded-full bg-bg-secondary text-text-secondary font-mono">
                            CVSS {d.cvss_score.toFixed(1)}
                          </span>
                        )}
                      </div>
                      {d.summary && (
                        <p className="mt-2 max-w-xs text-xs text-text-secondary leading-relaxed">
                          {truncateText(d.summary, 180)}
                        </p>
                      )}
                      {d.affected_range && (
                        <p className="mt-1 text-[10px] font-mono text-text-muted">
                          Affected: {truncateText(d.affected_range, 48)}
                        </p>
                      )}
                    </td>
                    <td className="py-3 align-top">
                      <div className="flex flex-wrap gap-1.5">
                        <RelevanceBadge relevance={d.relevance} />
                        <ReachabilityBadge
                          status={d.reachability_status}
                          confidence={d.reachability_confidence}
                        />
                        <EvidenceTypeBadge evidenceType={d.evidence_type} />
                      </div>
                      {d.usage_evidence && d.usage_evidence.length > 0 ? (
                        <p className="mt-2 text-[10px] text-text-muted">
                          {d.usage_evidence.length} code reference{d.usage_evidence.length === 1 ? "" : "s"} captured
                        </p>
                      ) : (
                        <p className="mt-2 text-[10px] text-text-muted">
                          No package usage evidence stored
                        </p>
                      )}
                    </td>
                    <td className="py-3 align-top">
                      <DependencyRiskBadge score={d.risk_score} />
                      {riskFactors.length > 0 && (
                        <p className="mt-2 text-[10px] leading-relaxed text-text-muted">
                          Factors: {riskFactors.join(", ")}
                        </p>
                      )}
                    </td>
                    <td className="py-3 align-top text-xs text-text-secondary leading-relaxed">
                      <div>{d.ai_assessment || "No explicit usage evidence captured."}</div>
                      {d.vulnerable_functions && d.vulnerable_functions.length > 0 && (
                        <div className="mt-2 text-[10px] text-text-muted">
                          Vulnerable functions: {d.vulnerable_functions.slice(0, 3).join(", ")}
                        </div>
                      )}
                      {usageHits.length > 0 && (
                        <details className="mt-2 group">
                          <summary className="cursor-pointer text-[10px] font-medium text-accent-primary hover:text-accent-primary/80 transition-colors">
                            Evidence details
                          </summary>
                          <ul className="mt-2 space-y-1 text-[10px] text-text-muted">
                            {usageHits.map((hit, index) => (
                              <li key={`${d.id}-usage-${index}`}>{formatDependencyUsageHit(hit)}</li>
                            ))}
                            {remainingUsageHits > 0 && (
                              <li>... and {remainingUsageHits} more evidence item{remainingUsageHits === 1 ? "" : "s"}</li>
                            )}
                          </ul>
                        </details>
                      )}
                    </td>
                  </tr>
                )})}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ── OWASP Top 10 Mapping ──────────────────────────────── */}
      {report?.owasp_mapping && Object.keys(report.owasp_mapping).length > 0 && (
        <OWASPSection mapping={report.owasp_mapping} />
      )}

      {/* ── Component Security Scorecard ───────────────────────── */}
      {report?.component_scores && Object.keys(report.component_scores).length > 0 && (
        <ComponentScorecard scores={report.component_scores} />
      )}

      {/* ── Software Bill of Materials ─────────────────────────── */}
      {report?.sbom && report.sbom.total_components > 0 && (
        <SBOMSection sbom={report.sbom} />
      )}

      {/* ── Scan Coverage ──────────────────────────────────────── */}
      {report?.scan_coverage && (
        <ScanCoverageSection coverage={report.scan_coverage} />
      )}

      {/* ── Methodology ───────────────────────────────────────── */}
      {(report?.methodology || report?.limitations) && (
        <section className="card-glow border-gradient">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-8 h-8 rounded-lg bg-accent-purple/10 flex items-center justify-center">
              <BookOpen className="w-4 h-4 text-accent-purple" />
            </div>
            <h2 className="text-lg font-semibold">Methodology & Limitations</h2>
          </div>
          {report.methodology && (
            <div className="text-sm text-text-secondary leading-relaxed space-y-2">
              {report.methodology.split("\n").filter(Boolean).map((p, i) => (
                <p key={i}>{p}</p>
              ))}
            </div>
          )}
          {report.limitations && (
            <div className="mt-4 p-4 rounded-xl bg-accent-warning/5 border border-accent-warning/15">
              <div className="flex items-center gap-2 mb-2">
                <Info className="w-4 h-4 text-accent-warning" />
                <span className="text-xs font-semibold text-accent-warning uppercase tracking-wider">
                  Limitations
                </span>
              </div>
              <p className="text-sm text-text-secondary leading-relaxed">
                {report.limitations}
              </p>
            </div>
          )}
        </section>
      )}

      {/* ── AI Chat Window ────────────────────────────────────── */}
      <ChatWindow
        scanId={scanId!}
        currentFile={currentFile}
        currentFileContent={currentFileContent}
        initialPrompt={chatPrompt}
        onPromptConsumed={() => setChatPrompt("")}
      />
    </div>
  );
}

/* ── Sub-components ───────────────────────────────────────────── */

function ConfidenceBar({ value }: { value: number }) {
  const pct = Math.round(value * 100);
  const color =
    pct >= 80 ? "bg-accent-danger" : pct >= 50 ? "bg-accent-warning" : "bg-accent-success";
  return (
    <div className="flex items-center gap-2 shrink-0">
      <div className="w-16 h-1.5 bg-bg-secondary rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-text-muted tabular-nums w-8">{pct}%</span>
    </div>
  );
}

function DetailBlock({
  icon,
  title,
  color,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  color: string;
  children: React.ReactNode;
}) {
  return (
    <div className="pl-10">
      <div className="flex items-center gap-2 mb-1.5">
        <span className={color}>{icon}</span>
        <span className={`text-xs font-semibold uppercase tracking-wider ${color}`}>
          {title}
        </span>
      </div>
      <p className="text-sm text-text-secondary leading-relaxed">{children}</p>
    </div>
  );
}

function RelevanceBadge({ relevance }: { relevance: string }) {
  const styles: Record<string, string> = {
    used: "bg-accent-danger/10 text-accent-danger",
    likely_used: "bg-accent-danger/10 text-accent-danger",
    transitive_only: "bg-accent-warning/10 text-accent-warning",
    unused: "bg-accent-success/10 text-accent-success",
    test_only: "bg-accent-primary/10 text-accent-primary",
    unknown: "bg-bg-secondary text-text-muted",
  };
  const labels: Record<string, string> = {
    used: "Used",
    likely_used: "Likely used",
    transitive_only: "Transitive only",
    unused: "Unused",
    test_only: "Test only",
    unknown: "Unknown",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${styles[relevance] || styles.unknown}`}>
      {labels[relevance] || relevance}
    </span>
  );
}

function ReachabilityBadge({
  status,
  confidence,
}: {
  status: string;
  confidence?: number | null;
}) {
  const styles: Record<string, string> = {
    reachable: "bg-accent-danger/10 text-accent-danger",
    potentially_reachable: "bg-orange-500/10 text-orange-400",
    no_path_found: "bg-accent-primary/10 text-accent-primary",
    not_applicable: "bg-accent-success/10 text-accent-success",
    unknown: "bg-bg-secondary text-text-muted",
  };
  const label = formatDependencyLabel(status);
  const confidenceLabel =
    typeof confidence === "number" ? ` ${Math.round(confidence * 100)}%` : "";
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${styles[status] || styles.unknown}`}>
      {label}
      {confidenceLabel}
    </span>
  );
}

function EvidenceTypeBadge({ evidenceType }: { evidenceType: string }) {
  const styles: Record<string, string> = {
    exact_package_match: "bg-accent-danger/10 text-accent-danger",
    canonical_package_match: "bg-accent-warning/10 text-accent-warning",
    artifact_alias_match: "bg-accent-primary/10 text-accent-primary",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${styles[evidenceType] || "bg-bg-secondary text-text-muted"}`}>
      {formatDependencyLabel(evidenceType)}
    </span>
  );
}

function DependencyRiskBadge({ score }: { score?: number | null }) {
  if (typeof score !== "number") {
    return <span className="text-[10px] text-text-muted">No risk score</span>;
  }

  const tone =
    score >= 800
      ? { text: "text-accent-danger", bar: "bg-accent-danger" }
      : score >= 600
      ? { text: "text-orange-400", bar: "bg-orange-400" }
      : score >= 350
      ? { text: "text-accent-warning", bar: "bg-accent-warning" }
      : { text: "text-accent-success", bar: "bg-accent-success" };

  return (
    <div>
      <div className={`font-mono text-xs font-semibold ${tone.text}`}>
        {Math.round(score)}/1000
      </div>
      <div className="mt-1 h-1.5 w-24 rounded-full bg-bg-secondary overflow-hidden">
        <div
          className={`h-full rounded-full ${tone.bar}`}
          style={{ width: `${Math.max(4, Math.min(100, score / 10))}%` }}
        />
      </div>
    </div>
  );
}

function truncateText(value: string, maxLength: number): string {
  return value.length > maxLength ? `${value.slice(0, maxLength - 3)}...` : value;
}

function formatDependencyUsageHit(hit: DependencyUsageEvidence): string {
  const kindMap: Record<string, string> = {
    import: "Import detected",
    reference: "Symbol reference",
    vulnerable_function: "Vulnerable function",
  };
  const parts = [kindMap[hit.kind || ""] || formatDependencyLabel(hit.kind || "usage")];
  if (hit.symbol) {
    parts.push(hit.symbol);
  }

  const location = [hit.file, typeof hit.line === "number" ? String(hit.line) : null]
    .filter(Boolean)
    .join(":");
  if (location) {
    parts.push(`in ${location}`);
  }
  if (hit.source) {
    parts.push(`via ${formatDependencyLabel(hit.source)}`);
  }
  if (typeof hit.confidence === "number") {
    parts.push(`${Math.round(hit.confidence * 100)}% confidence`);
  }
  return parts.join(" | ");
}

function formatDependencyRiskFactors(
  factors?: Record<string, number | string | boolean | null> | null
): string[] {
  if (!factors) {
    return [];
  }

  const labels: Record<string, string> = {
    base: "severity base",
    reachability: "reachability",
    relevance: "package usage",
    vulnerable_function_match: "function match",
    dev_dependency: "dev-only scope",
    fix_available: "fix available",
    hot_file_usage: "hot-file usage",
  };

  return Object.entries(factors)
    .filter(
      ([key, value]) =>
        !["base", "final"].includes(key) &&
        typeof value === "number" &&
        Number.isFinite(value) &&
        value !== 0
    )
    .map(([key, value]) => [key, value as number] as const)
    .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
    .slice(0, 3)
    .map(([key, value]) => `${labels[key] || formatDependencyLabel(key)} ${value > 0 ? "+" : ""}${Math.round(value)}`);
}

function formatDependencyLabel(value: string): string {
  return value
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function normalizeStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .map((item) => String(item ?? "").trim())
    .filter(Boolean);
}

function uniqueStrings(values: string[]): string[] {
  const seen = new Set<string>();
  const deduped: string[] = [];
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized) {
      continue;
    }
    const key = normalized.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduped.push(normalized);
  }
  return deduped;
}

function normalizeArchitectureComponent(component: unknown): ArchitectureComponent | null {
  if (typeof component === "string") {
    const name = component.trim();
    return name ? { name } : null;
  }

  const record = asRecord(component);
  if (!record) {
    return null;
  }

  const name = String(record.name || "").trim() || "Component";
  return {
    name,
    purpose: typeof record.purpose === "string" ? record.purpose : undefined,
    files: normalizeStringList(record.files),
    criticality: typeof record.criticality === "string" ? record.criticality : undefined,
    in_attack_surface: typeof record.in_attack_surface === "boolean" ? record.in_attack_surface : undefined,
    handles_user_input: typeof record.handles_user_input === "boolean" ? record.handles_user_input : undefined,
  };
}

function normalizeArchitectureEntryPoint(entryPoint: unknown): ArchitectureEntryPoint | null {
  if (typeof entryPoint === "string") {
    const path = entryPoint.trim();
    return path ? { path } : null;
  }

  const record = asRecord(entryPoint);
  if (!record) {
    return null;
  }

  const file = typeof record.file === "string" ? record.file.trim() : "";
  const fn = typeof record.function === "string" ? record.function.trim() : "";
  const path = typeof record.path === "string" ? record.path.trim() : "";
  const method = typeof record.method === "string" ? record.method.trim() : "";
  const type = typeof record.type === "string" ? record.type.trim() : "";
  const auth = typeof record.auth === "string" ? record.auth.trim() : "";
  const notes = typeof record.notes === "string" ? record.notes.trim() : "";

  if (!file && !fn && !path && !method && !type && !auth && !notes) {
    return null;
  }

  return {
    file: file || undefined,
    function: fn || undefined,
    type: type || undefined,
    method: method || undefined,
    path: path || undefined,
    auth: auth || undefined,
    notes: notes || undefined,
  };
}

function formatArchitectureEntryPoint(entryPoint: ArchitectureEntryPoint): string {
  const route = [entryPoint.method, entryPoint.path].filter(Boolean).join(" ").trim();
  const handler = [entryPoint.file, entryPoint.function].filter(Boolean).join(" -> ").trim();
  const typeLabel = entryPoint.type ? formatDependencyLabel(entryPoint.type) : "";
  return [route || null, handler || null, typeLabel || null].filter(Boolean).join(" | ") || "Mapped entry point";
}

function normalizeArchitectureDataFlow(flow: unknown): ArchitectureDataFlow | null {
  if (typeof flow === "string") {
    const summary = flow.trim();
    return summary ? { from: summary } : null;
  }

  const record = asRecord(flow);
  if (!record) {
    return null;
  }

  const from = typeof record.from === "string" ? record.from.trim() : "";
  const to = typeof record.to === "string" ? record.to.trim() : "";
  const data = typeof record.data === "string" ? record.data.trim() : "";
  const sensitive = typeof record.sensitive === "boolean" ? record.sensitive : undefined;

  if (!from && !to && !data && typeof sensitive !== "boolean") {
    return null;
  }

  return {
    from: from || undefined,
    to: to || undefined,
    data: data || undefined,
    sensitive,
  };
}

function formatArchitectureDataFlow(flow: ArchitectureDataFlow): string {
  const path = [flow.from || "source", flow.to || "destination"].join(" -> ");
  const detail = flow.data ? ` | ${flow.data}` : "";
  const sensitivity = flow.sensitive ? " | sensitive" : "";
  return `${path}${detail}${sensitivity}`;
}

function normalizeArchitectureAuthMechanism(mechanism: unknown): ArchitectureAuthMechanism | null {
  if (typeof mechanism === "string") {
    const type = mechanism.trim();
    return type ? { type } : null;
  }

  const record = asRecord(mechanism);
  if (!record) {
    return null;
  }

  const type = typeof record.type === "string" ? record.type.trim() : "";
  const implementation = typeof record.implementation === "string" ? record.implementation.trim() : "";
  const weaknesses = typeof record.weaknesses === "string" ? record.weaknesses.trim() : "";

  if (!type && !implementation && !weaknesses) {
    return null;
  }

  return {
    type: type || undefined,
    implementation: implementation || undefined,
    weaknesses: weaknesses || undefined,
  };
}

function normalizeArchitectureHotspot(hotspot: unknown): ArchitectureHotspot | null {
  if (typeof hotspot === "string") {
    const name = hotspot.trim();
    return name ? { name } : null;
  }

  const record = asRecord(hotspot);
  if (!record) {
    return null;
  }

  const name = String(record.name || "").trim() || "Component";
  const numericValue = (key: string) =>
    typeof record[key] === "number" && Number.isFinite(record[key]) ? (record[key] as number) : undefined;

  return {
    name,
    criticality: typeof record.criticality === "string" ? record.criticality : undefined,
    finding_count: numericValue("finding_count"),
    critical_count: numericValue("critical_count"),
    high_count: numericValue("high_count"),
    medium_count: numericValue("medium_count"),
    max_severity: typeof record.max_severity === "string" ? record.max_severity : undefined,
    in_attack_surface: typeof record.in_attack_surface === "boolean" ? record.in_attack_surface : undefined,
  };
}

function deriveAttackSurfacePoints(attackSurface: string[], entryPoints: ArchitectureEntryPoint[]): string[] {
  const entryPointPaths = entryPoints.map((entryPoint) => formatArchitectureEntryPoint(entryPoint));
  return uniqueStrings([...attackSurface, ...entryPointPaths]);
}

function extractExploitChainSteps(finding: Finding): string[] {
  const exploitEvidence = normalizeExploitEvidence(finding);
  if (exploitEvidence?.validation_steps?.length) {
    return uniqueStrings(exploitEvidence.validation_steps).slice(0, 6);
  }

  const textSources = [
    exploitEvidence?.attack_scenario,
    finding.description,
    finding.explanation,
    finding.impact,
  ].filter(Boolean) as string[];

  const bulletSteps = uniqueStrings(
    textSources
      .flatMap((value) => value.split(/\r?\n+/))
      .map((step) => step.replace(/^[\-\*\d\.\)\s]+/, "").trim())
      .filter((step) => step.length >= 20)
  );
  if (bulletSteps.length >= 2) {
    return bulletSteps.slice(0, 6);
  }

  const arrowSteps = uniqueStrings(
    textSources
      .flatMap((value) => value.split(/\s*(?:->|=>)\s*/))
      .map((step) => step.trim())
      .filter((step) => step.length >= 8)
  );
  return arrowSteps.length >= 2 ? arrowSteps.slice(0, 6) : [];
}

function createEmptyArchitecturePayload(diagrams: ArchitectureDiagram[] = []): ArchitecturePayload {
  return {
    analysisMarkdown: null,
    diagrams,
    components: [],
    auth_mechanisms: [],
    external_integrations: [],
    trust_boundaries: [],
    security_observations: [],
    component_hotspots: [],
    result_summary: {},
    entry_points: [],
    data_flows: [],
    attack_surface_points: [],
  };
}

function formatAdvisoryFunctionLabel(advisory: RelatedAdvisory): string {
  const functionName = advisory.function || advisory.imported_symbol || advisory.call_object;
  if (!functionName) {
    return "";
  }
  const line = typeof advisory.line === "number" ? ` line ${advisory.line}` : "";
  return `call ${functionName}${line}`;
}

function AdvisoryStrengthBadge({ strength }: { strength: string }) {
  const styles: Record<string, string> = {
    strong: "bg-accent-danger/10 text-accent-danger",
    medium: "bg-accent-warning/10 text-accent-warning",
    contextual: "bg-accent-primary/10 text-accent-primary",
    weak: "bg-bg-secondary text-text-muted",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${styles[strength] || styles.weak}`}>
      {formatDependencyLabel(strength)}
    </span>
  );
}

function AdvisoryEvidenceBadge({ evidenceType }: { evidenceType: string }) {
  const styles: Record<string, string> = {
    confirmed_vulnerable_dependency_function_match: "bg-accent-danger/10 text-accent-danger",
    import_confirmed_function_match: "bg-accent-warning/10 text-accent-warning",
    function_name_overlap: "bg-bg-secondary text-text-muted",
    related_by_cwe: "bg-accent-primary/10 text-accent-primary",
  };
  return (
    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${styles[evidenceType] || "bg-bg-secondary text-text-muted"}`}>
      {formatDependencyLabel(evidenceType)}
    </span>
  );
}

export function parseArchitecturePayload(
  architecture: string | null | undefined,
  diagramSpec?: string | null
): ArchitecturePayload {
  const fallbackDiagrams = diagramSpec
    ? [{ title: "Architecture Overview", description: "Primary report diagram", mermaid: diagramSpec }]
    : [];

  if (!architecture) {
    return createEmptyArchitecturePayload(fallbackDiagrams);
  }

  try {
    const parsed = JSON.parse(architecture) as Record<string, unknown>;
    if (!parsed || typeof parsed !== "object") {
      return { ...createEmptyArchitecturePayload(fallbackDiagrams), analysisMarkdown: architecture };
    }

    const rawDiagrams = Array.isArray(parsed.diagrams) ? parsed.diagrams : [];
    const diagrams = rawDiagrams
      .map((diagram) => (diagram && typeof diagram === "object" ? diagram as Record<string, unknown> : null))
      .filter(Boolean)
      .map((diagram) => ({
        title: String(diagram?.title || "Architecture"),
        description: String(diagram?.description || ""),
        mermaid: String(diagram?.mermaid || ""),
        kind: diagram?.kind ? String(diagram.kind) : undefined,
        imageUrl:
          typeof diagram?.imageUrl === "string"
            ? String(diagram.imageUrl)
            : typeof diagram?.image_url === "string"
            ? String(diagram.image_url)
            : undefined,
        highlights: Array.isArray(diagram?.highlights)
          ? diagram.highlights.map((item) => String(item))
          : undefined,
      }))
      .filter((diagram) => diagram.mermaid || fallbackDiagrams.length === 0);

    const entryPoints = Array.isArray(parsed.entry_points)
      ? parsed.entry_points
          .map((entryPoint) => normalizeArchitectureEntryPoint(entryPoint))
          .filter(Boolean) as ArchitectureEntryPoint[]
      : [];
    const dataFlows = Array.isArray(parsed.data_flows)
      ? parsed.data_flows
          .map((flow) => normalizeArchitectureDataFlow(flow))
          .filter(Boolean) as ArchitectureDataFlow[]
      : [];
    const attackSurface = normalizeStringList(parsed.attack_surface);
    const resultSummaryRecord = asRecord(parsed.result_summary);
    const resultSummary = resultSummaryRecord
      ? Object.fromEntries(
          Object.entries(resultSummaryRecord).filter(([, value]) => typeof value === "number" && Number.isFinite(value))
        ) as ArchitectureResultSummary
      : {};

    return {
      analysisMarkdown: typeof parsed.analysis_markdown === "string" ? parsed.analysis_markdown : null,
      diagrams: diagrams.length > 0 ? diagrams : fallbackDiagrams,
      components: Array.isArray(parsed.components)
        ? parsed.components
            .map((component) => normalizeArchitectureComponent(component))
            .filter(Boolean) as ArchitectureComponent[]
        : [],
      auth_mechanisms: Array.isArray(parsed.auth_mechanisms)
        ? parsed.auth_mechanisms
            .map((mechanism) => normalizeArchitectureAuthMechanism(mechanism))
            .filter(Boolean) as ArchitectureAuthMechanism[]
        : [],
      external_integrations: normalizeStringList(parsed.external_integrations),
      trust_boundaries: normalizeStringList(parsed.trust_boundaries),
      security_observations: normalizeStringList(parsed.security_observations),
      component_hotspots: Array.isArray(parsed.component_hotspots)
        ? parsed.component_hotspots
            .map((hotspot) => normalizeArchitectureHotspot(hotspot))
            .filter(Boolean) as ArchitectureHotspot[]
        : [],
      result_summary: resultSummary,
      entry_points: entryPoints,
      data_flows: dataFlows,
      attack_surface_points: deriveAttackSurfacePoints(attackSurface, entryPoints),
    };
  } catch {
    return {
      ...createEmptyArchitecturePayload(fallbackDiagrams),
      analysisMarkdown: architecture,
    };
  }
}

const LANG_EMOJI: Record<string, string> = {
  php: "\u{1F418}", javascript: "\u{1F7E8}", typescript: "\u{1F535}", python: "\u{1F40D}",
  java: "\u2615", kotlin: "\u{1F7E3}", go: "\u{1F439}", ruby: "\u{1F48E}",
  rust: "\u2699\uFE0F", csharp: "\u{1F7E2}", sql: "\u{1F5C4}\uFE0F", css: "\u{1F3A8}",
  html: "\u{1F310}", docker: "\u{1F433}", shell: "\u{1F4BB}", bash: "\u{1F4BB}",
};

function TechBadge({ name, variant }: { name: string; variant: "language" | "framework" }) {
  const emoji = LANG_EMOJI[name.toLowerCase()] || "\u{1F4C4}";
  const cls =
    variant === "language"
      ? "bg-accent-primary/10 text-accent-primary border-accent-primary/20"
      : "bg-accent-purple/10 text-accent-purple border-accent-purple/20";
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs font-medium ${cls}`}>
      <span className="text-sm leading-none">{emoji}</span>
      {name}
    </span>
  );
}

/* ── Codebase Statistics ────────────────────────────────────────── */

const LANG_COLORS: Record<string, string> = {
  python: "#3572A5", javascript: "#f1e05a", typescript: "#3178c6",
  java: "#b07219", kotlin: "#A97BFF", go: "#00ADD8",
  rust: "#dea584", ruby: "#701516", php: "#4F5D95",
  csharp: "#178600", c: "#555555", cpp: "#f34b7d",
  swift: "#F05138", html: "#e34c26", css: "#563d7c",
  shell: "#89e051", sql: "#e38c00", vue: "#41b883",
  dart: "#00B4AB", scala: "#c22d40",
};

function CodebaseStats({
  techStack,
  fingerprint,
}: {
  techStack: { languages?: string[]; frameworks?: string[] } | null;
  fingerprint: any;
}) {
  const languages = fingerprint?.languages as Array<{ name: string; file_count: number; percentage: number }> | undefined;

  if (!languages?.length) {
    return <p className="text-text-muted text-sm">No language data available.</p>;
  }

  const totalFiles = languages.reduce((sum, l) => sum + (l.file_count || 0), 0);

  return (
    <div className="space-y-4">
      {/* Total files */}
      <div className="text-center pb-3 border-b border-border/50">
        <p className="text-3xl font-bold font-mono text-accent-primary">{totalFiles.toLocaleString()}</p>
        <p className="text-xs text-text-muted">Source files</p>
      </div>

      {/* Language bars */}
      <div className="space-y-2.5">
        {languages.slice(0, 12).map((lang) => {
          const pct = totalFiles > 0 ? (lang.file_count / totalFiles) * 100 : 0;
          const color = LANG_COLORS[lang.name] || "#6b7280";
          return (
            <div key={lang.name} className="group">
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: color }} />
                  <span className="text-xs font-medium capitalize">{lang.name}</span>
                </div>
                <span className="text-[10px] text-text-muted font-mono tabular-nums">
                  {lang.file_count} <span className="text-text-muted/50">({pct.toFixed(0)}%)</span>
                </span>
              </div>
              <div className="w-full h-1.5 bg-bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{ width: `${Math.max(2, pct)}%`, backgroundColor: color }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Frameworks */}
      {techStack?.frameworks && techStack.frameworks.length > 0 && (
        <div className="pt-3 border-t border-border/50">
          <p className="text-[10px] text-text-muted uppercase tracking-wider mb-2">Frameworks</p>
          <div className="flex flex-wrap gap-1.5">
            {techStack.frameworks.map((f) => (
              <span key={f} className="text-[10px] px-2 py-0.5 rounded bg-bg-secondary text-text-secondary">
                {f}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Codebase Browser ──────────────────────────────────────────── */

const SEV_PRIORITY: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_DOT_COLOR: Record<string, string> = {
  critical: "text-accent-danger",
  high: "text-orange-400",
  medium: "text-accent-warning",
  low: "text-accent-success",
  info: "text-accent-primary",
};

interface FileNode {
  name: string;
  path: string;
  type: "file" | "dir";
  language?: string;
  size_bytes?: number;
  id?: string;
  children?: FileNode[];
}

function CodeBrowser({
  scanId,
  onFileSelect,
  findings,
  onAskAboutFile,
}: {
  scanId: string;
  onFileSelect: (path: string, content: string) => void;
  findings?: Finding[];
  onAskAboutFile?: (prompt: string) => void;
}) {
  const [tree, setTree] = useState<FileNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedFile, setSelectedFile] = useState<string>("");
  const [selectedFileLanguage, setSelectedFileLanguage] = useState<string>("");
  const [fileContent, setFileContent] = useState<string>("");
  const [fileLoading, setFileLoading] = useState(false);
  const [search, setSearch] = useState("");
  const [fileSearch, setFileSearch] = useState("");

  // Compute finding lines for the currently selected file
  const findingLinesForFile = selectedFile && findings
    ? findings
        .filter((f) => (f.file_paths || []).includes(selectedFile))
        .flatMap((f) => {
          // Check evidence for line ranges
          return (f.evidence || []).flatMap((ev) => {
            if (ev.line_range) {
              const parts = String(ev.line_range).split("-");
              const start = parseInt(parts[0], 10);
              const end = parseInt(parts[1] || parts[0], 10);
              if (!isNaN(start) && !isNaN(end)) {
                return Array.from({ length: end - start + 1 }, (_, i) => start + i);
              }
            }
            return [];
          });
        })
    : [];
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Load file tree
  useEffect(() => {
    (async () => {
      try {
        const data = await api.get<{ tree: FileNode[]; total_files: number }>(
          `/scans/${scanId}/files/tree`
        );
        setTree(data.tree);
        // Auto-expand first level
        const firstLevelDirs = data.tree.filter((n) => n.type === "dir").map((n) => n.path);
        setExpanded(new Set(firstLevelDirs));
      } catch {
        // No files
      } finally {
        setLoading(false);
      }
    })();
  }, [scanId]);

  const loadFile = async (node: FileNode) => {
    if (!node.id) return;
    setSelectedFile(node.path);
    setSelectedFileLanguage(node.language || "");
    setFileLoading(true);
    setFileSearch("");
    try {
      const data = await api.get<{ path: string; content: string; language: string }>(
        `/scans/${scanId}/files/${node.id}/content`
      );
      setFileContent(data.content);
      onFileSelect(data.path, data.content);
    } catch {
      setFileContent("[Failed to load file]");
    } finally {
      setFileLoading(false);
    }
  };

  const toggleDir = (path: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const filterTree = (nodes: FileNode[], query: string): FileNode[] => {
    if (!query) return nodes;
    const q = query.toLowerCase();
    return nodes
      .map((node) => {
        if (node.type === "dir") {
          const filteredChildren = filterTree(node.children || [], q);
          if (filteredChildren.length > 0) return { ...node, children: filteredChildren };
          return null;
        }
        return node.name.toLowerCase().includes(q) || node.path.toLowerCase().includes(q)
          ? node
          : null;
      })
      .filter(Boolean) as FileNode[];
  };

  const filteredTree = filterTree(tree, search);

  // Compute files that have findings and their highest severity
  const filesWithFindings = new Set(
    (findings || []).flatMap((f) => f.file_paths || []).filter(Boolean)
  );

  // Map file path → highest severity
  const fileSeverityMap = new Map<string, string>();
  for (const f of findings || []) {
    for (const fp of f.file_paths || []) {
      if (!fp) continue;
      const current = fileSeverityMap.get(fp);
      const currentPri = current ? (SEV_PRIORITY[current] ?? 0) : -1;
      const newPri = SEV_PRIORITY[f.severity] ?? 0;
      if (newPri > currentPri) {
        fileSeverityMap.set(fp, f.severity);
      }
    }
  }

  if (loading) return null;
  if (!tree.length) return null;

  return (
    <section className="card-glow border-gradient">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-accent-secondary/10 flex items-center justify-center">
          <FileCode2 className="w-4 h-4 text-accent-secondary" />
        </div>
        <h2 className="text-lg font-semibold">Source Code</h2>
      </div>

      <div className="flex gap-4" style={{ minHeight: 400, maxHeight: 700 }}>
        {/* File tree panel */}
        <div className="w-72 shrink-0 bg-[#0c0c14] rounded-xl border border-[#1a1a2e] flex flex-col overflow-hidden">
          <div className="p-2 border-b border-[#1a1a2e]">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter files..."
              className="w-full px-2.5 py-1.5 bg-bg-secondary border border-border rounded-lg text-xs text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-primary/50"
            />
          </div>
          <div className="flex-1 overflow-y-auto p-1 text-xs">
            <FileTreeView
              nodes={filteredTree}
              expanded={expanded}
              selectedPath={selectedFile}
              onToggle={toggleDir}
              onSelect={loadFile}
              depth={0}
              filesWithFindings={filesWithFindings}
              fileSeverityMap={fileSeverityMap}
              onSendToChat={(path) => {
                if (onAskAboutFile) {
                  onAskAboutFile(`Analyze the security of the file "${path}". What vulnerabilities exist? Are there any findings related to it?`);
                }
              }}
            />
          </div>
        </div>

        {/* Code viewer panel */}
        <div className="flex-1 bg-[#0c0c14] rounded-xl border border-[#1a1a2e] flex flex-col overflow-hidden">
          {selectedFile ? (
            <>
              <div className="px-4 py-2 border-b border-[#1a1a2e] flex items-center justify-between">
                <div className="flex items-center gap-2 min-w-0">
                  <FileCode2 className="w-3.5 h-3.5 text-text-muted shrink-0" />
                  <span className="text-xs text-text-secondary font-mono truncate">{selectedFile}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-text-muted" />
                    <input
                      type="text"
                      value={fileSearch}
                      onChange={(e) => setFileSearch(e.target.value)}
                      placeholder="Search in file..."
                      className="pl-7 pr-2 py-1 w-40 bg-bg-secondary border border-border rounded text-[10px] text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-primary/50"
                    />
                  </div>
                </div>
              </div>
              <div className="flex-1 overflow-auto">
                {fileLoading ? (
                  <div className="flex items-center justify-center py-12">
                    <Loader2 className="w-5 h-5 animate-spin text-text-muted" />
                  </div>
                ) : (
                  <CodeViewer
                    content={fileContent}
                    language={selectedFileLanguage}
                    searchQuery={fileSearch}
                    findingLines={findingLinesForFile}
                  />
                )}
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center text-text-muted text-sm">
              Select a file to view its contents
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

/* ── Code Viewer with syntax highlighting + search + finding markers ── */

function CodeViewer({
  content,
  language,
  searchQuery,
  findingLines,
}: {
  content: string;
  language: string;
  searchQuery: string;
  findingLines: number[];
}) {
  const codeRef = useRef<HTMLPreElement>(null);
  const findingLineSet = new Set(findingLines);

  useEffect(() => {
    // Apply highlight.js
    if (codeRef.current) {
      import("highlight.js/lib/common").then((hljs) => {
        const el = codeRef.current?.querySelector("code[data-highlight]");
        if (el) {
          try {
            // @ts-ignore
            delete el.dataset.highlighted;
            hljs.default.highlightElement(el as HTMLElement);
          } catch {
            // Language not supported
          }
        }
      });
    }
  }, [content, language]);

  const lines = content.split("\n");
  const lowerQuery = searchQuery.toLowerCase();

  return (
    <pre
      ref={codeRef}
      className="p-0 text-xs font-mono leading-relaxed whitespace-pre overflow-x-auto"
    >
      <code data-highlight className={`language-${language || "plaintext"}`} style={{ display: "none" }}>
        {content}
      </code>
      {lines.map((line, i) => {
        const lineNum = i + 1;
        const isFindingLine = findingLineSet.has(lineNum);
        const isSearchMatch = lowerQuery && line.toLowerCase().includes(lowerQuery);

        return (
          <div
            key={i}
            className={`flex ${
              isFindingLine
                ? "bg-accent-danger/10 border-l-2 border-accent-danger"
                : isSearchMatch
                ? "bg-accent-warning/10"
                : "hover:bg-bg-hover/20"
            }`}
          >
            <span className={`w-10 shrink-0 text-right pr-4 select-none tabular-nums ${
              isFindingLine ? "text-accent-danger/70" : "text-text-muted/40"
            }`}>
              {lineNum}
            </span>
            <span className={isFindingLine ? "text-text-primary" : ""}>{line || " "}</span>
          </div>
        );
      })}
    </pre>
  );
}

function _getHighestSeverity(
  node: FileNode,
  fileSeverityMap: Map<string, string>,
): string | null {
  if (node.type === "file") return fileSeverityMap.get(node.path) || null;
  if (!node.children) return null;
  let highest: string | null = null;
  let highestPri = -1;
  for (const child of node.children) {
    const childSev = _getHighestSeverity(child, fileSeverityMap);
    if (childSev && (SEV_PRIORITY[childSev] ?? 0) > highestPri) {
      highest = childSev;
      highestPri = SEV_PRIORITY[childSev] ?? 0;
    }
  }
  return highest;
}

function FileTreeView({
  nodes,
  expanded,
  selectedPath,
  onToggle,
  onSelect,
  depth,
  filesWithFindings,
  fileSeverityMap,
  onSendToChat,
}: {
  nodes: FileNode[];
  expanded: Set<string>;
  selectedPath: string;
  onToggle: (path: string) => void;
  onSelect: (node: FileNode) => void;
  depth: number;
  filesWithFindings?: Set<string>;
  fileSeverityMap?: Map<string, string>;
  onSendToChat?: (filePath: string) => void;
}) {
  return (
    <>
      {nodes.map((node) => {
        const severity = fileSeverityMap
          ? _getHighestSeverity(node, fileSeverityMap)
          : (filesWithFindings?.has(node.path) ? "medium" : null);
        const showAlert = !!severity;
        const dotColor = severity ? (SEV_DOT_COLOR[severity] || "text-accent-warning") : "";
        return (
          <div key={node.path}>
            <div className="flex items-center group/row">
              <button
                onClick={() => {
                  if (node.type === "dir") onToggle(node.path);
                  else onSelect(node);
                }}
                className={`flex-1 flex items-center gap-1.5 px-2 py-1 rounded text-left hover:bg-bg-hover/30 transition-colors ${
                  selectedPath === node.path ? "bg-accent-primary/10 text-accent-primary" : "text-text-secondary"
                }`}
                style={{ paddingLeft: depth * 14 + 8 }}
              >
                {node.type === "dir" ? (
                  <ChevronRight
                    className={`w-3 h-3 shrink-0 transition-transform ${
                      expanded.has(node.path) ? "rotate-90" : ""
                    }`}
                  />
                ) : (
                  <span className="w-3 shrink-0" />
                )}
                <span className={`truncate ${node.type === "dir" ? "font-medium" : "font-mono"}`}>
                  {node.name}
                </span>
                {showAlert && (
                  <AlertTriangle className={`w-3 h-3 ${dotColor} shrink-0`} />
                )}
                {node.language && !showAlert && (
                  <span className="ml-auto text-[9px] text-text-muted/50 shrink-0">{node.language}</span>
                )}
              </button>
              {/* Send to AI button — only for files */}
              {node.type === "file" && onSendToChat && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onSelect(node);
                    onSendToChat(node.path);
                  }}
                  className="px-1.5 py-0.5 rounded text-[9px] text-text-muted opacity-0 group-hover/row:opacity-100
                    hover:text-accent-primary hover:bg-accent-primary/10 transition-all shrink-0 mr-1"
                  title="Ask AI about this file"
                >
                  AI
                </button>
              )}
            </div>
            {node.type === "dir" && expanded.has(node.path) && node.children && (
              <FileTreeView
                nodes={node.children}
                expanded={expanded}
                selectedPath={selectedPath}
                onToggle={onToggle}
                onSelect={onSelect}
                depth={depth + 1}
                filesWithFindings={filesWithFindings}
                fileSeverityMap={fileSeverityMap}
                onSendToChat={onSendToChat}
              />
            )}
          </div>
        );
      })}
    </>
  );
}

/* ── Secrets Section with search/filter ─────────────────────────── */

function SecretsSection({ secrets }: { secrets: SecretCandidate[] }) {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [showAll, setShowAll] = useState(false);
  const [sectionOpen, setSectionOpen] = useState(false);
  const [revealedSecrets, setRevealedSecrets] = useState<Set<string>>(new Set());

  // Get unique types
  const secretTypes = [...new Set(secrets.map((s) => s.type))].sort();

  // Filter
  const filtered = secrets.filter((s) => {
    const matchesSearch =
      !search ||
      (s.file_path || "").toLowerCase().includes(search.toLowerCase()) ||
      s.type.toLowerCase().includes(search.toLowerCase());
    const matchesType = typeFilter === "all" || s.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const displayed = showAll ? filtered : filtered.slice(0, 20);

  return (
    <section className="card-glow border-gradient">
      <button
        onClick={() => setSectionOpen(!sectionOpen)}
        className="w-full flex items-center justify-between mb-4 group"
      >
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent-danger/10 flex items-center justify-center">
            <Key className="w-4 h-4 text-accent-danger" />
          </div>
          <h2 className="text-lg font-semibold">
            Secrets & Sensitive Data
            <span className="text-text-muted font-normal ml-2 text-base">
              ({filtered.length})
            </span>
          </h2>
        </div>
        <ChevronDown className={`w-5 h-5 text-text-muted transition-transform ${sectionOpen ? "rotate-0" : "-rotate-90"}`} />
      </button>

      {!sectionOpen && (
        <p className="text-sm text-text-muted">
          {filtered.length} potential secrets detected across the codebase. Click to expand and review.
        </p>
      )}

      {sectionOpen && (
      <div>
      {/* Search and filter bar */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <ScanLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by file, type, or pattern..."
            className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent-primary/50"
          />
        </div>
        <div className="flex gap-1 flex-wrap">
          <button
            onClick={() => setTypeFilter("all")}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              typeFilter === "all"
                ? "bg-accent-primary/15 text-accent-primary"
                : "bg-bg-secondary text-text-muted hover:text-text-secondary"
            }`}
          >
            All
          </button>
          {secretTypes.slice(0, 8).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(typeFilter === t ? "all" : t)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                typeFilter === t
                  ? "bg-accent-danger/15 text-accent-danger"
                  : "bg-bg-secondary text-text-muted hover:text-text-secondary"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Results table */}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left">
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Type</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">File</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Line</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Value</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Confidence</th>
            </tr>
          </thead>
          <tbody>
            {displayed.map((s) => {
              const isRevealed = revealedSecrets.has(s.id);
              return (
              <tr key={s.id} className="border-b border-border/30 hover:bg-bg-hover/20">
                <td className="py-2.5">
                  <span className="font-mono text-xs bg-accent-danger/10 text-accent-danger px-2 py-0.5 rounded">
                    {s.type}
                  </span>
                </td>
                <td className="py-2.5 text-text-secondary font-mono text-xs max-w-[300px] truncate">
                  {s.file_path}
                </td>
                <td className="py-2.5 text-text-muted tabular-nums">{s.line_number}</td>
                <td className="py-2.5">
                  {s.value_preview ? (
                    <div className="flex items-center gap-1.5">
                      <code className="font-mono text-xs max-w-[200px] truncate block">
                        {isRevealed ? s.value_preview : "••••••••••••"}
                      </code>
                      <button
                        onClick={() => {
                          setRevealedSecrets((prev) => {
                            const next = new Set(prev);
                            next.has(s.id) ? next.delete(s.id) : next.add(s.id);
                            return next;
                          });
                        }}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-bg-hover text-text-muted hover:text-text-primary shrink-0"
                      >
                        {isRevealed ? "Hide" : "Show"}
                      </button>
                    </div>
                  ) : (
                    <span className="text-text-muted text-xs">—</span>
                  )}
                </td>
                <td className="py-2.5">
                  {s.confidence != null && <ConfidenceBar value={s.confidence} />}
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Show more button */}
      {!showAll && filtered.length > 20 && (
        <button
          onClick={() => setShowAll(true)}
          className="mt-4 w-full py-2 text-sm text-accent-primary hover:text-accent-primary/80 bg-accent-primary/5 rounded-lg"
        >
          Show all {filtered.length} secrets
        </button>
      )}
      {showAll && filtered.length > 20 && (
        <button
          onClick={() => setShowAll(false)}
          className="mt-4 w-full py-2 text-sm text-text-muted hover:text-text-secondary bg-bg-secondary rounded-lg"
        >
          Show less
        </button>
      )}
      </div>
      )}
    </section>
  );
}

/* ── Mermaid: uses imported MermaidDiagram from @/components/MermaidDiagram ── */

/* (forceDarkThemeSvg + getMermaid + inline MermaidDiagram removed — using @/components/MermaidDiagram) */

/* MermaidDiagram is now imported from @/components/MermaidDiagram */

/* ── Diagram Viewer with tabs, fullscreen, zoom/pan ─────────────── */

type ArchitectureDiagram = {
  title: string;
  description?: string;
  mermaid: string;
  kind?: string;
  highlights?: string[];
  imageUrl?: string;
};

type ArchitectureComponent = {
  name?: string;
  purpose?: string;
  files?: string[];
  criticality?: string;
  in_attack_surface?: boolean;
  handles_user_input?: boolean;
};

type ArchitectureEntryPoint = {
  file?: string;
  function?: string;
  type?: string;
  method?: string;
  path?: string;
  auth?: string;
  notes?: string;
};

type ArchitectureDataFlow = {
  from?: string;
  to?: string;
  data?: string;
  sensitive?: boolean;
};

type ArchitectureAuthMechanism = {
  type?: string;
  implementation?: string;
  weaknesses?: string;
};

type ArchitectureHotspot = {
  name?: string;
  criticality?: string;
  finding_count?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  max_severity?: string;
  in_attack_surface?: boolean;
};

type ArchitectureResultSummary = {
  [key: string]: number | undefined;
  finding_count?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  exploit_chain_count?: number;
  advisory_correlated_count?: number;
  reachable_dependency_count?: number;
  active_dependency_count?: number;
  function_matched_dependency_count?: number;
  high_risk_dependency_count?: number;
};

type ArchitecturePayload = {
  analysisMarkdown: string | null;
  diagrams: ArchitectureDiagram[];
  components: ArchitectureComponent[];
  auth_mechanisms: ArchitectureAuthMechanism[];
  external_integrations: string[];
  trust_boundaries: string[];
  security_observations: string[];
  component_hotspots: ArchitectureHotspot[];
  result_summary: ArchitectureResultSummary;
  entry_points: ArchitectureEntryPoint[];
  data_flows: ArchitectureDataFlow[];
  attack_surface_points: string[];
};

export function ArchitectureAnalysisPanel({
  data,
  rawArchitecture,
}: {
  data: ArchitecturePayload;
  rawArchitecture: string | null;
}) {
  const hasStructuredContent =
    Object.keys(data.result_summary).length > 0 ||
    data.component_hotspots.length > 0 ||
    data.trust_boundaries.length > 0 ||
    data.auth_mechanisms.length > 0 ||
    data.external_integrations.length > 0 ||
    data.security_observations.length > 0 ||
    data.components.length > 0 ||
    data.entry_points.length > 0 ||
    data.data_flows.length > 0 ||
    data.attack_surface_points.length > 0;

  if (!hasStructuredContent) {
    const markdown = data.analysisMarkdown || rawArchitecture;
    if (!markdown) return null;
    return (
      <div className="prose prose-invert prose-sm max-w-none text-text-secondary
        prose-headings:text-text-primary prose-headings:font-semibold prose-headings:mt-3 prose-headings:mb-1
        prose-p:leading-relaxed prose-p:mb-2
        prose-ul:my-1 prose-li:my-0.5
        prose-strong:text-text-primary
        prose-code:text-accent-primary prose-code:bg-bg-secondary prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs">
        <ReactMarkdown>{markdown}</ReactMarkdown>
      </div>
    );
  }

  const resultSummary = data.result_summary;
  const hotspots = data.component_hotspots;
  const components = data.components;
  const authMechanisms = data.auth_mechanisms;
  const integrations = data.external_integrations;
  const trustBoundaries = data.trust_boundaries;
  const observations = data.security_observations;
  const entryPoints = data.entry_points;
  const dataFlows = data.data_flows;
  const attackSurfacePoints = data.attack_surface_points;
  const summaryBadges = [
    ["Verified findings", resultSummary.finding_count],
    ["Critical", resultSummary.critical_count],
    ["High", resultSummary.high_count],
    ["Medium", resultSummary.medium_count],
    ["Exploit chains", resultSummary.exploit_chain_count],
    ["Advisory correlated", resultSummary.advisory_correlated_count],
    ["Scanner-led", resultSummary.scanner_only_count],
    ["LLM-only", resultSummary.llm_only_count],
    ["Hybrid", resultSummary.hybrid_count],
    ["Static verification", resultSummary.statically_verified_count],
    ["Strong verification", resultSummary.strongly_verified_count],
    ["Runtime validated", resultSummary.runtime_validated_count],
    ["Merged duplicates", resultSummary.merged_duplicate_count],
    ["Reachable deps", resultSummary.reachable_dependency_count],
    ["Function matches", resultSummary.function_matched_dependency_count],
  ].filter(([, value]) => typeof value === "number" && value > 0);

  return (
    <div className="space-y-4 text-sm text-text-secondary">
      {summaryBadges.length > 0 && (
        <div>
          <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Result Summary</p>
          <div className="flex flex-wrap gap-2">
            {summaryBadges.map(([label, value]) => (
              <span key={label} className="inline-flex items-center gap-1.5 rounded-lg border border-border bg-bg-secondary px-2.5 py-1 text-xs">
                <span className="text-text-secondary">{label}</span>
                <span className="font-mono text-text-primary">{value}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {hotspots.length > 0 && (
        <div>
          <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Component Hotspots</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {hotspots.slice(0, 4).map((component) => (
              <div key={component.name} className="rounded-lg border border-border bg-bg-secondary/60 px-3 py-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-text-primary">{component.name}</span>
                  <div className="flex items-center gap-1.5">
                    {component.max_severity && (
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded ${
                          SEVERITY_COLORS[component.max_severity]?.bg || "bg-bg-tertiary"
                        } ${SEVERITY_COLORS[component.max_severity]?.text || "text-text-muted"}`}
                      >
                        {formatDependencyLabel(component.max_severity)}
                      </span>
                    )}
                    {component.criticality && (
                      <span className="text-[10px] text-text-muted bg-bg-tertiary px-1.5 py-0.5 rounded">
                        {formatDependencyLabel(component.criticality)}
                      </span>
                    )}
                  </div>
                </div>
                <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-text-muted">
                  <span>{component.finding_count || 0} findings</span>
                  {(component.critical_count || 0) > 0 && <span className="text-accent-danger">{component.critical_count} critical</span>}
                  {(component.high_count || 0) > 0 && <span className="text-orange-400">{component.high_count} high</span>}
                  {(component.medium_count || 0) > 0 && <span className="text-accent-warning">{component.medium_count} medium</span>}
                  {component.in_attack_surface && <span className="text-accent-primary">attack surface</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {(attackSurfacePoints.length > 0 || entryPoints.length > 0 || dataFlows.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {attackSurfacePoints.length > 0 && (
            <div>
              <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Concrete Attack Surface</p>
              <div className="space-y-1">
                {attackSurfacePoints.slice(0, 5).map((point) => (
                  <div key={point} className="rounded-lg bg-bg-secondary/60 px-2.5 py-1.5 text-xs font-mono text-text-secondary">
                    {point}
                  </div>
                ))}
              </div>
            </div>
          )}
          {entryPoints.length > 0 && (
            <div>
              <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Entry Points</p>
              <div className="space-y-1">
                {entryPoints.slice(0, 4).map((entryPoint, index) => (
                  <div key={`${formatArchitectureEntryPoint(entryPoint)}-${index}`} className="rounded-lg bg-bg-secondary/60 px-2.5 py-1.5 text-xs">
                    <div className="font-medium text-text-primary">{formatArchitectureEntryPoint(entryPoint)}</div>
                    {(entryPoint.auth || entryPoint.notes) && (
                      <div className="mt-1 text-text-muted">
                        {[entryPoint.auth ? `auth: ${entryPoint.auth}` : null, entryPoint.notes || null].filter(Boolean).join(" | ")}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          {dataFlows.length > 0 && (
            <div>
              <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Data Flows</p>
              <div className="space-y-1">
                {dataFlows.slice(0, 4).map((flow, index) => (
                  <div key={`${formatArchitectureDataFlow(flow)}-${index}`} className="rounded-lg bg-bg-secondary/60 px-2.5 py-1.5 text-xs">
                    <div className="font-medium text-text-primary">{`${flow.from || "source"} -> ${flow.to || "destination"}`}</div>
                    {flow.data && <div className="mt-1 text-text-muted">{flow.data}</div>}
                    {flow.sensitive && <div className="mt-1 text-accent-warning">Sensitive data path</div>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {(trustBoundaries.length > 0 || authMechanisms.length > 0 || integrations.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {trustBoundaries.length > 0 && (
            <div>
              <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Trust Boundaries</p>
              <div className="space-y-1">
                {trustBoundaries.slice(0, 4).map((boundary) => (
                  <div key={boundary} className="rounded-lg bg-bg-secondary/60 px-2.5 py-1.5 text-xs">
                    {boundary}
                  </div>
                ))}
              </div>
            </div>
          )}
          {authMechanisms.length > 0 && (
            <div>
              <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Auth Controls</p>
              <div className="space-y-1">
                {authMechanisms.slice(0, 3).map((auth, index) => (
                  <div key={`${auth.type || "auth"}-${index}`} className="rounded-lg bg-bg-secondary/60 px-2.5 py-1.5 text-xs">
                    <div className="font-medium text-text-primary">{formatDependencyLabel(auth.type || "unknown")}</div>
                    {auth.implementation && <div className="mt-1 text-text-muted">{truncateText(auth.implementation, 100)}</div>}
                    {auth.weaknesses && <div className="mt-1 text-accent-warning">{truncateText(auth.weaknesses, 100)}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}
          {integrations.length > 0 && (
            <div>
              <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">External Integrations</p>
              <div className="flex flex-wrap gap-1.5">
                {integrations.slice(0, 6).map((integration) => (
                  <span key={integration} className="rounded-lg bg-bg-secondary/60 px-2 py-1 text-xs">
                    {integration}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {observations.length > 0 && (
        <div>
          <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Security Observations</p>
          <div className="space-y-1">
            {observations.slice(0, 5).map((observation, index) => (
              <div key={`${index}-${observation.slice(0, 24)}`} className="rounded-lg bg-bg-secondary/60 px-2.5 py-1.5 text-xs leading-relaxed">
                {observation}
              </div>
            ))}
          </div>
        </div>
      )}

      {components.length > 0 && (
        <div>
          <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Architecture Components</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {components.slice(0, 6).map((component, index) => (
              <div key={`${component.name || "component"}-${index}`} className="rounded-lg border border-border bg-bg-secondary px-3 py-2 text-xs">
                <div className="font-medium text-text-primary">{component.name || "Component"}</div>
                {component.purpose && (
                  <div className="mt-1 text-text-muted leading-relaxed">{truncateText(component.purpose, 110)}</div>
                )}
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {component.criticality && (
                    <span className="rounded bg-bg-tertiary px-2 py-0.5 text-[10px] text-text-muted">
                      {formatDependencyLabel(component.criticality)}
                    </span>
                  )}
                  {component.in_attack_surface && (
                    <span className="rounded bg-accent-danger/10 px-2 py-0.5 text-[10px] text-accent-danger">
                      attack surface
                    </span>
                  )}
                  {component.handles_user_input && (
                    <span className="rounded bg-accent-warning/10 px-2 py-0.5 text-[10px] text-accent-warning">
                      user input
                    </span>
                  )}
                  {(component.files?.length ?? 0) > 0 && (
                    <span className="rounded bg-bg-tertiary px-2 py-0.5 text-[10px] text-text-muted">
                      {component.files?.length} files
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {data.analysisMarkdown && (
        <div className="prose prose-invert prose-sm max-w-none text-text-secondary
          prose-headings:text-text-primary prose-headings:font-semibold prose-headings:mt-3 prose-headings:mb-1
          prose-p:leading-relaxed prose-p:mb-2
          prose-ul:my-1 prose-li:my-0.5
          prose-strong:text-text-primary
          prose-code:text-accent-primary prose-code:bg-bg-secondary prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs">
          <ReactMarkdown>{data.analysisMarkdown}</ReactMarkdown>
        </div>
      )}
    </div>
  );
}

export function AttackPathPanel({
  attackSurfacePoints,
  entryPoints,
  dataFlows,
  fallbackMetrics,
}: {
  attackSurfacePoints: string[];
  entryPoints: ArchitectureEntryPoint[];
  dataFlows: ArchitectureDataFlow[];
  fallbackMetrics?: Record<string, number> | null;
}) {
  const fallbackEntries = Object.entries(fallbackMetrics || {}).sort((a, b) => b[1] - a[1]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded-lg bg-accent-danger/10 flex items-center justify-center">
          <Crosshair className="w-4 h-4 text-accent-danger" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-text-primary">Attack Paths</h3>
          <p className="text-xs text-text-muted">Concrete entry points and security-relevant flows</p>
        </div>
      </div>

      {attackSurfacePoints.length > 0 ? (
        <>
          <div className="flex flex-wrap gap-2">
            <span className="rounded-lg border border-border bg-bg-secondary px-2.5 py-1 text-xs text-text-secondary">
              <span className="font-mono text-text-primary">{attackSurfacePoints.length}</span> mapped surfaces
            </span>
            <span className="rounded-lg border border-border bg-bg-secondary px-2.5 py-1 text-xs text-text-secondary">
              <span className="font-mono text-text-primary">{entryPoints.length}</span> entry points
            </span>
            <span className="rounded-lg border border-border bg-bg-secondary px-2.5 py-1 text-xs text-text-secondary">
              <span className="font-mono text-text-primary">{dataFlows.length}</span> traced flows
            </span>
          </div>

          <div className="space-y-2">
            {attackSurfacePoints.slice(0, 5).map((point) => (
              <div
                key={point}
                className="rounded-lg border border-accent-danger/15 bg-accent-danger/5 px-3 py-2 text-xs font-mono text-text-secondary"
              >
                {point}
              </div>
            ))}
          </div>

          {dataFlows.length > 0 && (
            <div className="pt-3 border-t border-border/30">
              <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium mb-2">Flow Preview</p>
              <div className="space-y-1.5">
                {dataFlows.slice(0, 3).map((flow, index) => (
                  <div key={`${formatArchitectureDataFlow(flow)}-${index}`} className="rounded-lg bg-bg-secondary/60 px-3 py-2 text-xs">
                    <div className="font-medium text-text-primary">{`${flow.from || "source"} -> ${flow.to || "destination"}`}</div>
                    {flow.data && <div className="mt-1 text-text-muted">{flow.data}</div>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      ) : fallbackEntries.length > 0 ? (
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            Concrete routes were not mapped for this scan. Showing the finding-derived surface mix instead.
          </p>
          <div className="space-y-2">
            {fallbackEntries.slice(0, 6).map(([label, count]) => (
              <div key={label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-text-secondary">{label}</span>
                  <span className="font-mono text-text-primary">{count}</span>
                </div>
                <div className="h-1.5 rounded-full bg-bg-secondary overflow-hidden">
                  <div
                    className="h-full rounded-full bg-accent-primary"
                    style={{ width: `${Math.max(8, Math.min(100, count * 12))}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <p className="text-sm text-text-muted">No concrete attack paths were mapped for this report.</p>
      )}
    </div>
  );
}

export function ExploitChainsSection({ findings }: { findings: Finding[] }) {
  return (
    <section className="card-glow border-gradient space-y-4">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-accent-danger/10 flex items-center justify-center">
          <ListTree className="w-4 h-4 text-accent-danger" />
        </div>
        <div>
          <h2 className="text-lg font-semibold">Exploit Chains</h2>
          <p className="text-sm text-text-muted">Multi-step attack paths synthesized from verified findings and exploit evidence.</p>
        </div>
      </div>

      <div className="space-y-4">
        {findings.map((finding) => {
          const exploitEvidence = normalizeExploitEvidence(finding);
          const steps = extractExploitChainSteps(finding);
          const relatedPaths = uniqueStrings([
            ...(exploitEvidence?.related_entry_points || []),
            ...(exploitEvidence?.related_taint_flows || []),
          ]);
          const severityTone = SEVERITY_COLORS[finding.severity] || SEVERITY_COLORS.info;

          return (
            <div key={finding.id} className="rounded-2xl border border-border bg-bg-secondary/40 p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-base font-semibold text-text-primary">{finding.title}</h3>
                    <span className={`rounded-full px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider ${severityTone.bg} ${severityTone.text}`}>
                      {finding.severity}
                    </span>
                    <span className="rounded-full bg-bg-tertiary px-2.5 py-1 text-[10px] font-mono text-text-muted">
                      {Math.round((finding.confidence || 0) * 100)}% confidence
                    </span>
                  </div>
                  <p className="mt-2 text-sm text-text-secondary leading-relaxed">{finding.description}</p>
                </div>
              </div>

              {(exploitEvidence?.target_route || exploitEvidence?.attack_scenario || finding.impact) && (
                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                  {exploitEvidence?.target_route && (
                    <div className="rounded-lg bg-bg-tertiary/70 px-3 py-2">
                      <p className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Target Route</p>
                      <p className="font-mono text-xs text-text-primary">{exploitEvidence.target_route}</p>
                    </div>
                  )}
                  {(exploitEvidence?.attack_scenario || finding.impact) && (
                    <div className="rounded-lg bg-bg-tertiary/70 px-3 py-2 md:col-span-2">
                      <p className="text-[10px] uppercase tracking-wider text-text-muted mb-1">Chain Outcome</p>
                      <p className="text-text-secondary leading-relaxed">
                        {exploitEvidence?.attack_scenario || finding.impact}
                      </p>
                    </div>
                  )}
                </div>
              )}

              {relatedPaths.length > 0 && (
                <div className="mt-4">
                  <p className="text-[10px] uppercase tracking-wider text-text-muted mb-2">Chain Anchors</p>
                  <div className="flex flex-wrap gap-1.5">
                    {relatedPaths.slice(0, 8).map((path) => (
                      <span key={`${finding.id}-${path}`} className="rounded-lg bg-bg-tertiary px-2 py-1 text-[11px] font-mono text-text-secondary">
                        {path}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {steps.length > 0 && (
                <div className="mt-4">
                  <p className="text-[10px] uppercase tracking-wider text-text-muted mb-2">Observed Steps</p>
                  <ol className="space-y-2">
                    {steps.map((step, index) => (
                      <li key={`${finding.id}-step-${index}`} className="flex gap-3 text-sm text-text-secondary">
                        <span className="mt-0.5 inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-primary/10 text-[10px] font-semibold text-accent-primary">
                          {index + 1}
                        </span>
                        <span className="leading-relaxed">{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {exploitEvidence?.exploit_template && (
                <div className="mt-4 rounded-lg overflow-hidden border border-border">
                  <div className="bg-bg-tertiary px-3 py-1.5 border-b border-border">
                    <span className="text-[10px] text-text-muted uppercase tracking-wider font-medium">Exploit Template</span>
                  </div>
                  <pre className="bg-[#0b0f19] text-[11px] leading-relaxed text-text-secondary overflow-x-auto p-4">
                    {exploitEvidence.exploit_template}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function DiagramViewer({
  scanId,
  architectureData,
  hasDiagramImage,
  diagramCount,
}: {
  scanId: string;
  architectureData: ArchitecturePayload;
  hasDiagramImage: boolean;
  diagramCount: number;
}) {
  const [activeTab, setActiveTab] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });
  const containerRef = useRef<HTMLDivElement>(null);
  const diagrams: ArchitectureDiagram[] =
    architectureData.diagrams.length > 0
      ? architectureData.diagrams
      : (diagramCount > 0 || hasDiagramImage)
      ? Array.from({ length: Math.max(diagramCount, hasDiagramImage ? 1 : 0) }, (_, index) => ({
          title: index === 0 ? "Architecture Overview" : `Architecture Diagram ${index + 1}`,
          description: "Rendered report diagram",
          mermaid: "",
          kind: undefined,
          highlights: [],
          imageUrl: `/api/scans/${scanId}/report/diagram/${index}`,
        }))
      : [];

  // If no diagrams array, fall back to single diagram image
  const hasTabs = diagrams.length > 1;
  if (diagrams.length === 0) {
    return null;
  }

  const handleWheel = useCallback((e: WheelEvent) => {
    if (e.cancelable) {
      e.preventDefault();
    }
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom((z) => Math.max(0.3, Math.min(5, z + delta)));
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    container.addEventListener("wheel", handleWheel, { passive: false });
    return () => {
      container.removeEventListener("wheel", handleWheel);
    };
  }, [handleWheel]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setDragging(true);
    dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging) return;
    const dx = e.clientX - dragStart.current.x;
    const dy = e.clientY - dragStart.current.y;
    setPan({ x: dragStart.current.panX + dx, y: dragStart.current.panY + dy });
  }, [dragging]);

  const handleMouseUp = useCallback(() => setDragging(false), []);

  const resetView = useCallback(() => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
  }, []);

  const viewer = (
    <div className={fullscreen ? "fixed inset-0 z-50 bg-[#08080f] flex flex-col" : ""}>
      {/* Header */}
      <div className={`flex items-center justify-between ${fullscreen ? "px-6 py-3 border-b border-border" : "mb-4"}`}>
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent-secondary/10 flex items-center justify-center">
            <FileCode2 className="w-4 h-4 text-accent-secondary" />
          </div>
          <h2 className="text-lg font-semibold">Architecture</h2>
        </div>

        <div className="flex items-center gap-2">
          {/* Zoom controls */}
          <div className="flex items-center gap-1 bg-bg-secondary rounded-lg p-1">
            <button onClick={() => setZoom((z) => Math.max(0.3, z - 0.2))} className="p-1.5 hover:bg-bg-hover rounded" title="Zoom out">
              <ZoomOut className="w-3.5 h-3.5 text-text-muted" />
            </button>
            <span className="text-[10px] text-text-muted font-mono w-10 text-center tabular-nums">
              {Math.round(zoom * 100)}%
            </span>
            <button onClick={() => setZoom((z) => Math.min(5, z + 0.2))} className="p-1.5 hover:bg-bg-hover rounded" title="Zoom in">
              <ZoomIn className="w-3.5 h-3.5 text-text-muted" />
            </button>
            <button onClick={resetView} className="p-1.5 hover:bg-bg-hover rounded" title="Reset view">
              <Move className="w-3.5 h-3.5 text-text-muted" />
            </button>
          </div>

          {/* Download buttons */}
          <div className="flex items-center gap-1 bg-bg-secondary rounded-lg p-1">
            <button
              onClick={() => {
                const svgEl = containerRef.current?.querySelector("svg");
                if (!svgEl) return;
                const svgStr = new XMLSerializer().serializeToString(svgEl);
                const blob = new Blob([svgStr], { type: "image/svg+xml" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `${diagrams[activeTab]?.title || "diagram"}.svg`;
                a.click();
                URL.revokeObjectURL(url);
              }}
              className="p-1.5 hover:bg-bg-hover rounded text-text-muted hover:text-text-secondary"
              title="Download SVG"
            >
              <span className="text-[9px] font-bold">SVG</span>
            </button>
            <button
              onClick={() => {
                const svgEl = containerRef.current?.querySelector("svg");
                if (!svgEl) return;
                const svgStr = new XMLSerializer().serializeToString(svgEl);
                const canvas = document.createElement("canvas");
                const ctx = canvas.getContext("2d");
                if (!ctx) return;
                const img = new Image();
                const svgBlob = new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" });
                const url = URL.createObjectURL(svgBlob);
                img.onload = () => {
                  canvas.width = img.width * 2;
                  canvas.height = img.height * 2;
                  ctx.scale(2, 2);
                  ctx.fillStyle = "#0c0c14";
                  ctx.fillRect(0, 0, canvas.width, canvas.height);
                  ctx.drawImage(img, 0, 0);
                  const pngUrl = canvas.toDataURL("image/png");
                  const a = document.createElement("a");
                  a.href = pngUrl;
                  a.download = `${diagrams[activeTab]?.title || "diagram"}.png`;
                  a.click();
                  URL.revokeObjectURL(url);
                };
                img.src = url;
              }}
              className="p-1.5 hover:bg-bg-hover rounded text-text-muted hover:text-text-secondary"
              title="Download PNG"
            >
              <span className="text-[9px] font-bold">PNG</span>
            </button>
          </div>

          <button
            onClick={() => { setFullscreen(!fullscreen); resetView(); }}
            className="p-2 hover:bg-bg-hover rounded-lg"
            title={fullscreen ? "Exit fullscreen" : "Fullscreen"}
          >
            {fullscreen ? <Minimize2 className="w-4 h-4 text-text-muted" /> : <Maximize2 className="w-4 h-4 text-text-muted" />}
          </button>

          {fullscreen && (
            <button onClick={() => setFullscreen(false)} className="p-2 hover:bg-bg-hover rounded-lg" title="Close">
              <X className="w-4 h-4 text-text-muted" />
            </button>
          )}
        </div>
      </div>

      {/* Diagram tabs */}
      {hasTabs && (
        <div className={`flex gap-1 ${fullscreen ? "px-6 py-2" : "mb-3"}`}>
          {diagrams.map((d, i) => (
            <button
              key={i}
              onClick={() => { setActiveTab(i); resetView(); }}
              className={`px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                activeTab === i
                  ? "bg-accent-secondary/15 text-accent-secondary"
                  : "bg-bg-secondary text-text-muted hover:text-text-secondary"
              }`}
            >
              {d.title}
            </button>
          ))}
        </div>
      )}

      {/* Diagram canvas */}
      <div
        ref={containerRef}
        className={`rounded-xl overflow-hidden bg-[#0c0c14] border border-[#1a1a2e] ${
          fullscreen ? "flex-1 m-4 mt-0" : ""
        }`}
        style={{ cursor: dragging ? "grabbing" : "grab", minHeight: fullscreen ? undefined : 400 }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <div
          className="w-full h-full flex items-center justify-center p-6"
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: "center center",
            transition: dragging ? "none" : "transform 0.15s ease-out",
            minHeight: fullscreen ? "100%" : 400,
          }}
        >
          <MermaidDiagram
            spec={diagrams[activeTab]?.mermaid || ""}
            id={`diagram-${activeTab}`}
            fallbackImage={
              diagrams[activeTab]?.imageUrl
              || (((diagramCount > activeTab) || (activeTab === 0 && hasDiagramImage))
                ? `/api/scans/${scanId}/report/diagram/${activeTab}`
                : undefined)
            }
          />
        </div>
      </div>

      {/* Description */}
      {(diagrams[activeTab]?.description || diagrams[activeTab]?.highlights?.length) && (
        <div className={`mt-2 space-y-2 ${fullscreen ? "px-6 pb-3" : ""}`}>
          {diagrams[activeTab]?.description && (
            <p className="text-xs text-text-muted">{diagrams[activeTab].description}</p>
          )}
          {diagrams[activeTab]?.kind && (
            <div className="flex flex-wrap gap-1.5">
              {diagramFamilyLabel(diagrams[activeTab].kind) && (
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-accent-primary/10 text-accent-primary font-medium">
                  {diagramFamilyLabel(diagrams[activeTab].kind)}
                </span>
              )}
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-accent-secondary/10 text-accent-secondary font-medium">
                {formatDependencyLabel(diagrams[activeTab].kind || "diagram")}
              </span>
            </div>
          )}
          {diagrams[activeTab]?.highlights?.length ? (
            <div className="flex flex-wrap gap-1.5">
              {diagrams[activeTab].highlights!.slice(0, 4).map((highlight, index) => (
                <span
                  key={`${activeTab}-highlight-${index}`}
                  className="text-[10px] px-2 py-1 rounded-lg bg-bg-secondary text-text-muted"
                >
                  {highlight}
                </span>
              ))}
            </div>
          ) : null}
        </div>
      )}
    </div>
  );

  if (fullscreen) return viewer;

  return (
    <section className="card-glow border-gradient">
      {viewer}
    </section>
  );
}

/* ── Risk Score Banner ──────────────────────────────────────────── */

const GRADE_STYLES: Record<string, { bg: string; text: string; glow: string }> = {
  A: { bg: "bg-accent-success/15", text: "text-accent-success", glow: "shadow-accent-success/20" },
  B: { bg: "bg-accent-primary/15", text: "text-accent-primary", glow: "shadow-accent-primary/20" },
  C: { bg: "bg-accent-warning/15", text: "text-accent-warning", glow: "shadow-accent-warning/20" },
  D: { bg: "bg-orange-500/15", text: "text-orange-400", glow: "shadow-orange-400/20" },
  F: { bg: "bg-accent-danger/15", text: "text-accent-danger", glow: "shadow-accent-danger/20" },
};

function RiskScoreBanner({
  grade,
  score,
  findingCount,
  criticalCount,
  highCount,
}: {
  grade: string;
  score: number;
  findingCount: number;
  criticalCount: number;
  highCount: number;
}) {
  const gs = GRADE_STYLES[grade] || GRADE_STYLES.C;

  const summary =
    grade === "A"
      ? "No significant security issues identified."
      : grade === "B"
      ? "Minor issues found. Low overall risk."
      : grade === "C"
      ? "Moderate security concerns requiring attention."
      : grade === "D"
      ? "Significant security issues. Remediation recommended before production."
      : "Critical security failures. Immediate remediation required.";

  return (
    <div className={`rounded-2xl border border-border ${gs.bg} p-6`}>
      <div className="flex items-center gap-6">
        <div className={`w-20 h-20 rounded-2xl ${gs.bg} flex items-center justify-center shadow-lg ${gs.glow}`}>
          <span className={`text-4xl font-black ${gs.text}`}>{grade}</span>
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-1">
            <h2 className="text-lg font-semibold">Security Risk Assessment</h2>
            <span className="text-xs text-text-muted font-mono">Score: {score}/100</span>
          </div>
          <p className="text-sm text-text-secondary">{summary}</p>
          <div className="flex gap-4 mt-2 text-xs text-text-muted">
            <span>{findingCount} findings</span>
            {criticalCount > 0 && <span className="text-accent-danger">{criticalCount} critical</span>}
            {highCount > 0 && <span className="text-orange-400">{highCount} high</span>}
          </div>
        </div>
        {/* Score bar */}
        <div className="w-48 shrink-0">
          <div className="w-full h-3 bg-bg-secondary rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-1000 ${
                score <= 15 ? "bg-accent-success" : score <= 35 ? "bg-accent-warning" : "bg-accent-danger"
              }`}
              style={{ width: `${Math.max(3, score)}%` }}
            />
          </div>
          <div className="flex justify-between text-[9px] text-text-muted mt-1 font-mono">
            <span>Low risk</span>
            <span>High risk</span>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ── OWASP Top 10 Section ──────────────────────────────────────── */

const OWASP_ORDER = ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"];

function OWASPSection({ mapping }: { mapping: Record<string, OWASPEntry> }) {
  return (
    <section className="card-glow border-gradient">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-accent-secondary/10 flex items-center justify-center">
          <Shield className="w-4 h-4 text-accent-secondary" />
        </div>
        <h2 className="text-lg font-semibold">OWASP Top 10 Mapping</h2>
      </div>

      <div className="grid grid-cols-2 gap-3">
        {OWASP_ORDER.map((code) => {
          const entry = mapping[code];
          const hasFindings = entry && entry.count > 0;

          return (
            <div
              key={code}
              className={`flex items-center gap-3 rounded-xl p-3 border transition-all ${
                hasFindings
                  ? "border-border bg-bg-card"
                  : "border-transparent bg-bg-secondary/30 opacity-50"
              }`}
            >
              <span className={`text-xs font-bold font-mono w-8 shrink-0 ${hasFindings ? "text-accent-secondary" : "text-text-muted"}`}>
                {code}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium truncate">
                  {entry?.name || code}
                </p>
              </div>
              {hasFindings ? (
                <div className="flex items-center gap-2 shrink-0">
                  <span className={`badge badge-${entry.max_severity} text-[9px]`}>
                    {entry.max_severity.toUpperCase()}
                  </span>
                  <span className="text-xs font-mono text-text-muted">{entry.count}</span>
                </div>
              ) : (
                <span className="text-[9px] text-text-muted">No findings</span>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

/* ── Component Security Scorecard ──────────────────────────────── */

function ComponentScorecard({ scores }: { scores: Record<string, ComponentScore> }) {
  const sorted = Object.entries(scores).sort(
    (a, b) => a[1].score - b[1].score // worst first
  );
  const [expandedComp, setExpandedComp] = useState<Set<string>>(new Set());

  return (
    <section className="card-glow border-gradient">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-accent-purple/10 flex items-center justify-center">
          <Layers className="w-4 h-4 text-accent-purple" />
        </div>
        <h2 className="text-lg font-semibold">Component Security Scorecard</h2>
      </div>

      {/* Grade Legend */}
      <div className="flex flex-wrap items-center gap-3 mb-4 p-3 rounded-xl bg-bg-secondary/50 border border-border/30">
        <span className="text-[10px] text-text-muted uppercase tracking-wider font-medium mr-1">Grading Scale:</span>
        {[
          { grade: "A", range: "90-100", desc: "Excellent", color: "bg-accent-success/15 text-accent-success" },
          { grade: "B", range: "75-89", desc: "Good", color: "bg-blue-500/15 text-blue-400" },
          { grade: "C", range: "50-74", desc: "Fair", color: "bg-accent-warning/15 text-accent-warning" },
          { grade: "D", range: "25-49", desc: "Poor", color: "bg-orange-500/15 text-orange-400" },
          { grade: "F", range: "0-24", desc: "Failing", color: "bg-accent-danger/15 text-accent-danger" },
        ].map((g) => (
          <span key={g.grade} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium ${g.color}`}>
            <span className="font-black">{g.grade}</span>
            <span className="opacity-70">{g.range}</span>
            <span className="opacity-50">({g.desc})</span>
          </span>
        ))}
        <span className="text-[10px] text-text-muted ml-auto">Score = 100 minus weighted finding penalty. Click a row for details.</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left">
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Component</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Grade</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Score</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Criticality</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Findings</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Attack Surface</th>
            </tr>
          </thead>
          <tbody>
            {sorted.map(([name, comp]) => {
              const gs = GRADE_STYLES[comp.grade] || GRADE_STYLES.C;
              const isOpen = expandedComp.has(name);
              const hasSevs = comp.severities && Object.keys(comp.severities).length > 0;
              return (
                <Fragment key={name}>
                <tr
                  className={`border-b border-border/30 hover:bg-bg-hover/20 cursor-pointer transition-colors ${isOpen ? "bg-bg-hover/10" : ""}`}
                  onClick={() => setExpandedComp((prev) => {
                    const next = new Set(prev);
                    next.has(name) ? next.delete(name) : next.add(name);
                    return next;
                  })}
                >
                  <td className="py-2.5 font-medium">
                    <div className="flex items-center gap-1.5">
                      <ChevronRight className={`w-3 h-3 text-text-muted transition-transform ${isOpen ? "rotate-90" : ""}`} />
                      {name}
                    </div>
                  </td>
                  <td className="py-2.5">
                    <span className={`inline-flex items-center justify-center w-7 h-7 rounded-lg text-sm font-black ${gs.bg} ${gs.text}`}>
                      {comp.grade}
                    </span>
                  </td>
                  <td className="py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-bg-secondary rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${
                            comp.score >= 75 ? "bg-accent-success" : comp.score >= 45 ? "bg-accent-warning" : "bg-accent-danger"
                          }`}
                          style={{ width: `${comp.score}%` }}
                        />
                      </div>
                      <span className="text-xs text-text-muted font-mono">{comp.score}</span>
                    </div>
                  </td>
                  <td className="py-2.5">
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                      comp.criticality === "critical" ? "bg-accent-danger/10 text-accent-danger" :
                      comp.criticality === "high" ? "bg-orange-500/10 text-orange-400" :
                      comp.criticality === "medium" ? "bg-accent-warning/10 text-accent-warning" :
                      "bg-bg-secondary text-text-muted"
                    }`}>
                      {comp.criticality}
                    </span>
                  </td>
                  <td className="py-2.5 font-mono text-xs text-text-muted">{comp.finding_count}</td>
                  <td className="py-2.5">
                    {comp.in_attack_surface ? (
                      <span className="text-[10px] text-accent-danger bg-accent-danger/10 px-2 py-0.5 rounded-full font-medium">Exposed</span>
                    ) : (
                      <span className="text-[10px] text-text-muted">Internal</span>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr>
                    <td colSpan={6} className="py-3 px-6 bg-bg-secondary/30">
                      <div className="space-y-2">
                        {hasSevs ? (
                          <div>
                            <span className="text-xs font-medium text-text-primary">Finding Breakdown: </span>
                            <span className="text-xs text-text-secondary">
                              {Object.entries(comp.severities)
                                .sort((a, b) => (SEV_PRIORITY[b[0]] ?? 0) - (SEV_PRIORITY[a[0]] ?? 0))
                                .map(([sev, count]) => `${count} ${sev}`)
                                .join(", ")}
                            </span>
                          </div>
                        ) : (
                          <span className="text-xs text-text-muted">No findings in this component.</span>
                        )}
                        <div className="flex gap-4 text-xs text-text-muted">
                          <span>Criticality: <strong className="text-text-secondary">{comp.criticality}</strong></span>
                          <span>Attack surface: <strong className="text-text-secondary">{comp.in_attack_surface ? "Externally exposed" : "Internal only"}</strong></span>
                          <span>Score penalty: <strong className="text-text-secondary">{comp.score < 100 ? `-${(100 - comp.score).toFixed(1)} points` : "None"}</strong></span>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/* ── SBOM Section ──────────────────────────────────────────────── */

function SBOMSection({ sbom }: { sbom: SBOMData }) {
  const [showAll, setShowAll] = useState(false);
  const displayed = showAll ? sbom.components : sbom.components.slice(0, 20);

  return (
    <section className="card-glow border-gradient">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-accent-primary/10 flex items-center justify-center">
            <ListTree className="w-4 h-4 text-accent-primary" />
          </div>
          <h2 className="text-lg font-semibold">
            Software Bill of Materials
            <span className="text-text-muted font-normal ml-2 text-base">
              ({sbom.total_components} components)
            </span>
          </h2>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {Object.entries(sbom.ecosystems).map(([eco, count]) => (
            <span key={eco} className="px-2 py-0.5 rounded bg-bg-secondary text-text-muted">
              {eco}: {count}
            </span>
          ))}
          {sbom.vulnerable_components > 0 && (
            <span className="px-2 py-0.5 rounded bg-accent-danger/10 text-accent-danger font-medium">
              {sbom.vulnerable_components} vulnerable
            </span>
          )}
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left">
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Package</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Version</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Ecosystem</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Type</th>
              <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Status</th>
            </tr>
          </thead>
          <tbody>
            {displayed.map((comp, i) => (
              <tr
                key={`${comp.name}-${i}`}
                className={`border-b border-border/30 hover:bg-bg-hover/20 ${
                  comp.vulnerable ? "bg-accent-danger/[0.03]" : ""
                }`}
              >
                <td className="py-2 font-mono text-xs font-medium">{comp.name}</td>
                <td className="py-2 text-text-muted font-mono text-xs">{comp.version || "—"}</td>
                <td className="py-2 text-text-muted text-xs">{comp.ecosystem}</td>
                <td className="py-2">
                  <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                    comp.is_dev ? "bg-bg-secondary text-text-muted" : "bg-accent-primary/10 text-accent-primary"
                  }`}>
                    {comp.is_dev ? "dev" : "prod"}
                  </span>
                </td>
                <td className="py-2">
                  {comp.vulnerable ? (
                    <span className="text-[10px] text-accent-danger bg-accent-danger/10 px-2 py-0.5 rounded-full font-medium">
                      {comp.vulnerability_count} CVE{comp.vulnerability_count > 1 ? "s" : ""}
                    </span>
                  ) : (
                    <span className="text-[10px] text-accent-success">OK</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {sbom.components.length > 20 && (
        <button
          onClick={() => setShowAll(!showAll)}
          className="mt-3 text-xs text-accent-primary hover:text-accent-primary/80 transition-colors"
        >
          {showAll ? "Show less" : `Show all ${sbom.components.length} components`}
        </button>
      )}
    </section>
  );
}

/* ── Scan Coverage Section ─────────────────────────────────────── */

function ScanCoverageSection({ coverage }: { coverage: ScanCoverage }) {
  const aiPct = coverage.total_files > 0
    ? Math.round((coverage.files_inspected_by_ai / coverage.total_files) * 100)
    : 0;
  const scannerRuns = Object.values(coverage.scanner_runs || {}) as ScannerRunSummary[];

  return (
    <section className="card-glow border-gradient">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-accent-success/10 flex items-center justify-center">
          <ScanLine className="w-4 h-4 text-accent-success" />
        </div>
        <h2 className="text-lg font-semibold">Scan Coverage</h2>
      </div>

      {coverage.degraded_coverage && (
        <div className="mb-4 rounded-xl border border-accent-warning/20 bg-accent-warning/10 px-4 py-3 text-sm text-accent-warning">
          Scanner coverage was degraded. At least one scanner failed or completed with errors, so clean coverage should be treated as partial.
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-xl bg-bg-secondary/50 p-3 text-center">
          <p className="text-xl font-bold font-mono text-text-primary">{coverage.total_files.toLocaleString()}</p>
          <p className="text-[10px] text-text-muted mt-0.5">Total files</p>
        </div>
        <div className="rounded-xl bg-bg-secondary/50 p-3 text-center">
          <p className="text-xl font-bold font-mono text-accent-primary">{coverage.files_inspected_by_ai}</p>
          <p className="text-[10px] text-text-muted mt-0.5">AI inspected ({aiPct}%)</p>
        </div>
        <div className="rounded-xl bg-bg-secondary/50 p-3 text-center">
          <p className="text-xl font-bold font-mono text-text-primary">{coverage.ai_calls_made}</p>
          <p className="text-[10px] text-text-muted mt-0.5">AI calls made</p>
        </div>
        <div className="rounded-xl bg-bg-secondary/50 p-3 text-center">
          <p className="text-xl font-bold font-mono text-accent-secondary capitalize">{coverage.scan_mode}</p>
          <p className="text-[10px] text-text-muted mt-0.5">Scan mode</p>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-2">
        {coverage.scanners_used.map((s) => (
          <span key={s} className="text-[10px] px-2 py-0.5 rounded bg-accent-primary/10 text-accent-primary font-mono">
            {s}
          </span>
        ))}
        {coverage.is_apk && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-accent-warning/10 text-accent-warning font-mono">
            APK decompilation
          </span>
        )}
        {coverage.is_monorepo && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-accent-secondary/10 text-accent-secondary font-mono">
            Monorepo
          </span>
        )}
        {coverage.obfuscated_files > 0 && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-accent-danger/10 text-accent-danger font-mono">
            {coverage.obfuscated_files} obfuscated files
          </span>
        )}
        {coverage.files_skipped_size > 0 && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-accent-warning/10 text-accent-warning font-mono">
            {coverage.files_skipped_size} skipped (size)
          </span>
        )}
        {(coverage.ignored_file_count || 0) > 0 && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-bg-secondary text-text-secondary font-mono">
            {coverage.ignored_file_count} ignored by scope policy
          </span>
        )}
        {coverage.has_doc_intelligence && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-accent-success/10 text-accent-success font-mono">
            {coverage.doc_files_read} docs analysed
          </span>
        )}
      </div>

      {scannerRuns.length > 0 && (
        <div className="mt-5 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {scannerRuns.map((run) => {
            const tone =
              run.status === "failed"
                ? "border-accent-danger/30 bg-accent-danger/10"
                : run.status === "degraded"
                ? "border-accent-warning/30 bg-accent-warning/10"
                : "border-accent-success/20 bg-accent-success/10";
            const textTone =
              run.status === "failed"
                ? "text-accent-danger"
                : run.status === "degraded"
                ? "text-accent-warning"
                : "text-accent-success";
            return (
              <div key={run.scanner} className={`rounded-xl border p-3 ${tone}`}>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs font-semibold uppercase tracking-wide">{run.scanner}</span>
                  <span className={`text-[10px] font-mono uppercase ${textTone}`}>{run.status}</span>
                </div>
                <div className="mt-2 flex items-center gap-3 text-xs text-text-secondary">
                  <span>{run.hit_count} hits</span>
                  <span>{run.duration_ms}ms</span>
                </div>
                {run.errors[0] && (
                  <p className="mt-2 text-xs leading-relaxed text-text-secondary">
                    {run.errors[0]}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      )}

      {(coverage.repo_ignore_file || (coverage.managed_paths_ignored?.length ?? 0) > 0) && (
        <div className="mt-4 text-xs text-text-muted space-y-1.5">
          {coverage.repo_ignore_file && (
            <p>Repo ignore file: <code>{coverage.repo_ignore_file}</code></p>
          )}
          {(coverage.managed_paths_ignored?.length ?? 0) > 0 && (
            <p>Managed path exclusions: {coverage.managed_paths_ignored?.slice(0, 6).join(", ")}</p>
          )}
        </div>
      )}
    </section>
  );
}
