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
import { useState, useRef, useCallback, useEffect, createContext, useContext, Fragment } from "react";
import ReactMarkdown from "react-markdown";
import { api } from "@/api/client";
import ChatWindow from "@/components/ChatWindow";
import { MermaidDiagram } from "@/components/MermaidDiagram";
import {
  SeverityDonut,
  ScannerHitsChart,
  LanguageChart,
  CategoryChart,
  ConfidenceDistribution,
  AttackSurfaceRadar,
  DependencyRiskDonut,
} from "@/components/charts/Charts";
import type {
  Report,
  Finding,
  SecretCandidate,
  DependencyFinding,
  OWASPEntry,
  ComponentScore,
  SBOMData,
  ScanCoverage,
} from "@/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS: Record<string, { bg: string; text: string; bar: string; hex: string }> = {
  critical: { bg: "bg-accent-danger/10", text: "text-accent-danger", bar: "bg-accent-danger", hex: "#ef4444" },
  high: { bg: "bg-orange-500/10", text: "text-orange-400", bar: "bg-orange-400", hex: "#fb923c" },
  medium: { bg: "bg-accent-warning/10", text: "text-accent-warning", bar: "bg-accent-warning", hex: "#f59e0b" },
  low: { bg: "bg-accent-success/10", text: "text-accent-success", bar: "bg-accent-success", hex: "#22c55e" },
  info: { bg: "bg-accent-primary/10", text: "text-accent-primary", bar: "bg-accent-primary", hex: "#38bdf8" },
};

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

  const activeSecrets = secrets?.filter((s) => !s.is_false_positive) ?? [];

  const [exportError, setExportError] = useState<string | null>(null);

  const handleExport = async (format: "pdf" | "docx") => {
    setExporting(format);
    setExportError(null);
    try {
      const result = await api.post<{ id: string }>(
        `/scans/${scanId}/report/export`,
        { format }
      );
      window.open(`/api/scans/${scanId}/report/export/${result.id}/download`);
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

              {/* Attack Surface Overview */}
              {report.attack_surface && Object.keys(report.attack_surface).length > 0 && (
                <div className="mt-4 pt-4 border-t border-border/30">
                  <h3 className="text-sm font-semibold text-text-primary mb-3">Attack Surface</h3>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(report.attack_surface as Record<string, number>)
                      .sort((a, b) => (b[1] as number) - (a[1] as number))
                      .map(([key, val]) => (
                        <span key={key} className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${
                          (val as number) > 30 ? "bg-accent-danger/10 text-accent-danger border-accent-danger/20"
                          : (val as number) > 10 ? "bg-accent-warning/10 text-accent-warning border-accent-warning/20"
                          : "bg-bg-secondary text-text-muted border-border"
                        }`}>
                          {key}
                          <span className="font-mono text-[10px] opacity-70">{String(val)}</span>
                        </span>
                      ))
                    }
                  </div>
                </div>
              )}

              {/* Key Architecture Notes */}
              {report.architecture && (
                <details className="mt-2 group">
                  <summary className="flex items-center gap-2 cursor-pointer text-sm font-semibold text-text-primary hover:text-accent-primary transition-colors select-none">
                    <ChevronDown className="w-4 h-4 transition-transform group-open:rotate-0 -rotate-90" />
                    Architecture Analysis
                  </summary>
                  <div className="mt-3 pl-6 prose prose-invert prose-sm max-w-none text-text-secondary
                    prose-headings:text-text-primary prose-headings:font-semibold prose-headings:mt-3 prose-headings:mb-1
                    prose-p:leading-relaxed prose-p:mb-2
                    prose-ul:my-1 prose-li:my-0.5
                    prose-strong:text-text-primary
                    prose-code:text-accent-primary prose-code:bg-bg-secondary prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-xs
                    max-h-[500px] overflow-y-auto">
                    <ReactMarkdown>{report.architecture}</ReactMarkdown>
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
      {report?.has_diagram_image && (
        <DiagramViewer scanId={scanId!} architecture={report?.architecture} />
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
        const exploitableCount = findings?.filter((f) => f.exploit_template).length ?? 0;
        const cveCount = findings?.filter((f) => f.related_cves && f.related_cves.length > 0).length ?? 0;
        const critHighCount = (sevCounts["critical"] || 0) + (sevCounts["high"] || 0);
        return (
          <section className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[
              { label: "Total Findings", value: findings?.length ?? 0, color: "text-accent-warning" },
              { label: "Critical / High", value: critHighCount, color: critHighCount > 0 ? "text-accent-danger" : "text-accent-success" },
              { label: "Exploitable (PoC)", value: exploitableCount, color: exploitableCount > 0 ? "text-accent-danger" : "text-text-muted" },
              { label: "CVE Correlated", value: cveCount, color: cveCount > 0 ? "text-orange-400" : "text-text-muted" },
              { label: "Dep. Risks", value: depFindings?.length ?? 0, color: (depFindings?.length ?? 0) > 0 ? "text-accent-warning" : "text-text-muted" },
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

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
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

          {/* Finding categories */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 min-h-[300px]">
            {findings && findings.length > 0 ? (
              <CategoryChart
                categories={
                  findings.reduce((acc, f) => {
                    const cat = f.category || "uncategorized";
                    acc[cat] = (acc[cat] || 0) + 1;
                    return acc;
                  }, {} as Record<string, number>)
                }
              />
            ) : (
              <p className="text-text-muted text-sm">No findings</p>
            )}
          </div>
        </div>

        {/* Second row: radar + languages + dependency risks */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-8 pt-6 border-t border-border/30">
          {/* Attack surface radar */}
          <div className="bg-[#0c0c14] rounded-xl border border-[#1a1a2e] p-6 flex items-center justify-center min-h-[280px]">
            {report?.attack_surface ? (
              <AttackSurfaceRadar metrics={report.attack_surface as Record<string, number>} size={260} />
            ) : (
              <p className="text-text-muted text-sm">No attack surface data</p>
            )}
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
              const withCVEs = findings.filter((f) => f.related_cves && f.related_cves.length > 0);

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

                  {withCVEs.length > 0 && (
                    <p>
                      <strong className="text-text-primary">{withCVEs.length} findings</strong> were correlated with known CVE
                      entries in the advisory database, indicating that similar vulnerability patterns have been publicly
                      documented and may have known exploit techniques.
                    </p>
                  )}

                  <h3 className="text-base font-semibold text-text-primary mt-4">Methodology</h3>
                  <p>
                    The analysis was performed using a multi-pass approach combining automated static analysis scanners
                    (Semgrep, Bandit, ESLint, secrets detection, dependency audit) with AI-powered code investigation.
                    The AI investigator inspected {report?.scan_coverage?.files_analysed || "multiple"} source files,
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
                    <ConfidenceBar value={f.confidence} />
                  </button>

                  {/* Expanded detail */}
                  {isExpanded && (
                    <div className="mt-4 pt-4 border-t border-border/50 space-y-5">
                      {/* Description */}
                      <p className="text-sm text-text-secondary leading-relaxed pl-10">
                        {f.description}
                      </p>

                      {/* Related CVEs */}
                      {f.related_cves && f.related_cves.length > 0 && (
                        <div className="pl-10 space-y-1.5">
                          <p className="text-[10px] text-text-muted uppercase tracking-wider font-medium">Related CVEs</p>
                          {f.related_cves.map((cve) => (
                            <div key={cve.cve_id} className="flex items-start gap-2 text-xs bg-accent-danger/5 border border-accent-danger/10 rounded-lg px-3 py-2">
                              <span className="font-mono text-accent-danger font-medium shrink-0">{cve.cve_id}</span>
                              <span className="text-text-secondary">{cve.summary}</span>
                              {cve.package && (
                                <span className="ml-auto shrink-0 text-[10px] text-text-muted bg-bg-secondary px-1.5 py-0.5 rounded">
                                  {cve.package}
                                </span>
                              )}
                            </div>
                          ))}
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
                      {f.exploit_difficulty && (
                        <div className="pl-10">
                          <div className={`rounded-xl p-4 border ${
                            f.exploit_difficulty === "easy"
                              ? "bg-accent-danger/5 border-accent-danger/20"
                              : f.exploit_difficulty === "moderate"
                              ? "bg-accent-warning/5 border-accent-warning/20"
                              : "bg-bg-secondary/50 border-border"
                          }`}>
                            <div className="flex items-center gap-3 mb-2">
                              <Crosshair className={`w-4 h-4 ${
                                f.exploit_difficulty === "easy" ? "text-accent-danger" :
                                f.exploit_difficulty === "moderate" ? "text-accent-warning" :
                                "text-text-muted"
                              }`} />
                              <span className="text-xs font-semibold uppercase tracking-wider">
                                Exploit Difficulty: {f.exploit_difficulty}
                              </span>
                            </div>
                            {f.attack_scenario && (
                              <p className="text-sm text-text-secondary leading-relaxed mb-3">
                                {f.attack_scenario}
                              </p>
                            )}
                            {f.exploit_prerequisites && f.exploit_prerequisites.length > 0 && (
                              <div className="mb-3">
                                <span className="text-xs text-text-muted">Prerequisites: </span>
                                <span className="text-xs text-text-secondary">
                                  {f.exploit_prerequisites.join(", ")}
                                </span>
                              </div>
                            )}
                            {f.exploit_template && (
                              <div className="rounded-lg overflow-hidden border border-border mt-2">
                                <div className="bg-bg-tertiary px-3 py-1.5 border-b border-border">
                                  <span className="text-[10px] text-text-muted uppercase tracking-wider font-medium">
                                    Proof of Concept
                                  </span>
                                </div>
                                <pre className="bg-bg-secondary px-3 py-2 text-xs font-mono overflow-x-auto text-accent-danger/80">
                                  {f.exploit_template}
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
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Package</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Installed</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Severity</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Advisory</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Fixed In</th>
                  <th className="pb-3 font-medium text-text-muted text-xs uppercase tracking-wider">Relevance</th>
                </tr>
              </thead>
              <tbody>
                {depFindings.map((d) => (
                  <tr key={d.id} className="border-b border-border/30 hover:bg-bg-hover/20">
                    <td className="py-2.5 font-mono text-xs font-medium">{d.package_name}</td>
                    <td className="py-2.5 text-text-muted font-mono text-xs">{d.installed_version}</td>
                    <td className="py-2.5">
                      {d.severity && (
                        <span className={`badge badge-${d.severity}`}>
                          {d.severity.toUpperCase()}
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 text-xs font-mono text-text-muted">{d.advisory_id}</td>
                    <td className="py-2.5 text-accent-success font-mono text-xs">{d.fixed_version}</td>
                    <td className="py-2.5">
                      <RelevanceBadge relevance={d.relevance} />
                    </td>
                  </tr>
                ))}
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
        reportSummary={report?.app_summary || ""}
        riskGrade={report?.risk_grade}
        findingsCount={findings?.length ?? 0}
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
    likely_used: "bg-accent-danger/10 text-accent-danger",
    unused: "bg-accent-success/10 text-accent-success",
    test_only: "bg-accent-primary/10 text-accent-primary",
    unknown: "bg-bg-secondary text-text-muted",
  };
  const labels: Record<string, string> = {
    likely_used: "Used",
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

function DiagramViewer({ scanId, architecture }: { scanId: string; architecture: string | null }) {
  const [activeTab, setActiveTab] = useState(0);
  const [fullscreen, setFullscreen] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });
  const containerRef = useRef<HTMLDivElement>(null);

  // Parse diagrams from architecture JSON
  let diagrams: Array<{ title: string; description: string; mermaid: string }> = [];
  try {
    if (architecture) {
      const arch = JSON.parse(architecture);
      diagrams = arch.diagrams || [];
    }
  } catch {
    // Not JSON — legacy single diagram
  }

  // If no diagrams array, fall back to single diagram image
  const hasTabs = diagrams.length > 1;

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom((z) => Math.max(0.3, Math.min(5, z + delta)));
  }, []);

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
        onWheel={handleWheel}
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
            fallbackImage={activeTab === 0 ? `/api/scans/${scanId}/report/diagram` : undefined}
          />
        </div>
      </div>

      {/* Description */}
      {diagrams[activeTab]?.description && (
        <p className={`text-xs text-text-muted mt-2 ${fullscreen ? "px-6 pb-3" : ""}`}>
          {diagrams[activeTab].description}
        </p>
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

  return (
    <section className="card-glow border-gradient">
      <div className="flex items-center gap-3 mb-4">
        <div className="w-8 h-8 rounded-lg bg-accent-success/10 flex items-center justify-center">
          <ScanLine className="w-4 h-4 text-accent-success" />
        </div>
        <h2 className="text-lg font-semibold">Scan Coverage</h2>
      </div>

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
        {coverage.has_doc_intelligence && (
          <span className="text-[10px] px-2 py-0.5 rounded bg-accent-success/10 text-accent-success font-mono">
            {coverage.doc_files_read} docs analysed
          </span>
        )}
      </div>
    </section>
  );
}
