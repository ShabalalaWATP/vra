import { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import AnimatedCounter from "@/components/ui/AnimatedCounter";
import TypingText from "@/components/ui/TypingText";
import HudFrame from "@/components/ui/HudFrame";
import {
  Search,
  Brain,
  Bug,
  ShieldCheck,
  FileText,
  Loader2,
  CheckCircle2,
  XCircle,
  ArrowRight,
  FileCode2,
  Radar,
  Package,
  StopCircle,
  Smartphone,
  Clock,
  Zap,
  Activity,
  Timer,
} from "lucide-react";
import { api } from "@/api/client";
import { useWebSocket } from "@/hooks/useWebSocket";
import type { Project, Scan, ScanEvent, ScannerRunSummary } from "@/types";

/* ── Phase definitions matching the backend stages ─────────── */
const APK_PHASE = {
  id: "decompiling",
  label: "APK Decompilation",
  icon: Smartphone,
  color: "text-accent-purple",
  bgColor: "bg-accent-purple",
  gradientFrom: "#8b5cf6",
  gradientTo: "#a855f7",
  description: "Decompile APK to Java source code using jadx",
  substeps: [
    "Extract DEX bytecode from APK",
    "Decompile to Java source files",
    "Parse AndroidManifest.xml",
    "Extract resources and assets",
  ],
};

const BASE_PHASES = [
  {
    id: "triage",
    label: "Repository Triage",
    icon: Search,
    color: "text-accent-primary",
    bgColor: "bg-accent-primary",
    gradientFrom: "#00d4ff",
    gradientTo: "#0ea5e9",
    description: "Fingerprint, scan, and prioritise the codebase",
    substeps: [
      "Detect languages, frameworks, and workspaces",
      "Index source files and detect obfuscation",
      "Read project documentation (README, docs)",
      "Run Semgrep, Bandit, ESLint, CodeQL in parallel",
      "Scan for secrets and credentials",
      "Match dependency advisories",
      "Analyse documentation with AI",
      "Score and prioritise files",
      "Fingerprint technology versions for CVE matching",
    ],
  },
  {
    id: "understanding",
    label: "Application Understanding",
    icon: Brain,
    color: "text-accent-secondary",
    bgColor: "bg-accent-secondary",
    gradientFrom: "#64ffda",
    gradientTo: "#14b8a6",
    description: "Build a model of what the application does",
    substeps: [
      "Read high-priority source files",
      "Classify components and layers",
      "Identify trust boundaries and entry points",
      "Map data flows and attack surface",
      "Generate architecture diagram spec",
    ],
  },
  {
    id: "dependencies",
    label: "Dependency Analysis",
    icon: Package,
    color: "text-accent-warning",
    bgColor: "bg-accent-warning",
    gradientFrom: "#eab308",
    gradientTo: "#f59e0b",
    description: "Assess whether vulnerable dependencies are exploitable",
    substeps: [
      "Trace package imports across codebase",
      "Match packages to vulnerability advisories",
      "Assess exploitability in application context",
      "Boost priority of files using vulnerable packages",
    ],
  },
  {
    id: "investigation",
    label: "Vulnerability Investigation",
    icon: Bug,
    color: "text-accent-orange",
    bgColor: "bg-accent-orange",
    gradientFrom: "#f97316",
    gradientTo: "#ea580c",
    description: "Multi-pass adaptive vulnerability hunting",
    substeps: [
      "Inspect suspicious code paths",
      "Trace data flows from input to sink",
      "Check for calls to CVE-linked vulnerable functions",
      "Pull in related files for context",
      "Re-prioritise files based on findings",
      "Collect supporting and opposing evidence",
    ],
  },
  {
    id: "targeted_scan",
    label: "Targeted Scanning",
    icon: Radar,
    color: "text-accent-primary",
    bgColor: "bg-accent-primary",
    gradientFrom: "#06b6d4",
    gradientTo: "#0284c7",
    description: "AI-selected follow-up scanner rules on hot files",
    substeps: [
      "Select scanner rules based on findings",
      "Run targeted Semgrep, Bandit, ESLint, and CodeQL passes",
      "Investigate new scanner hits",
      "Feed results back into investigation",
    ],
  },
  {
    id: "verification",
    label: "Finding Verification",
    icon: ShieldCheck,
    color: "text-accent-purple",
    bgColor: "bg-accent-purple",
    gradientFrom: "#8b5cf6",
    gradientTo: "#7c3aed",
    description: "Challenge findings, detect exploit chains, verify taint flows",
    substeps: [
      "Verify each finding against source code",
      "Check for framework protections",
      "Detect multi-step exploit chains",
      "Verify data flow paths (source to sink)",
      "Correlate findings with CVE/advisory database",
      "Adjust severity and confidence scores",
      "Re-investigate if confirmation rate is low",
    ],
  },
  {
    id: "reporting",
    label: "Report Generation",
    icon: FileText,
    color: "text-accent-success",
    bgColor: "bg-accent-success",
    gradientFrom: "#22c55e",
    gradientTo: "#16a34a",
    description: "Generate professional analyst-quality report",
    substeps: [
      "Write finding narratives and remediation",
      "Generate executive summary",
      "Render architecture diagram with tech icons",
      "Prepare PDF and DOCX exports",
    ],
  },
];

function getPhases(isApk: boolean) {
  return isApk ? [APK_PHASE, ...BASE_PHASES] : BASE_PHASES;
}

/* ── ETA estimation ────────────────────────────────────────── */
function useETA(scanStartedAt: string | null, phaseIdx: number, _totalPhases: number, aiCalls?: number, maxAiCalls?: number) {
  const [eta, setEta] = useState<string | null>(null);

  useEffect(() => {
    const compute = () => {
      if (!scanStartedAt || phaseIdx < 0) {
        setEta(null);
        return;
      }

      const elapsed = Date.now() - new Date(scanStartedAt).getTime();
      if (elapsed < 10000) {
        setEta("Estimating...");
        return;
      }

      // Each phase isn't equal weight — investigation is longest
      const weights = [1, 1.5, 0.5, 4, 0.5, 2.5, 1]; // triage, understanding, deps, investigation, targeted, verification, reporting
      const totalWeight = weights.reduce((a, b) => a + b, 0);
      const completedWeight = weights.slice(0, phaseIdx).reduce((a, b) => a + b, 0);
      const currentWeight = weights[Math.min(phaseIdx, weights.length - 1)] || 1;

      // Use AI call progress for investigation phase (phaseIdx=3) if available
      let progressInPhase = 0.5;
      if (phaseIdx === 3 && aiCalls && maxAiCalls && maxAiCalls > 0) {
        progressInPhase = Math.min(0.95, aiCalls / maxAiCalls);
      }

      const weightedProgress = (completedWeight + currentWeight * progressInPhase) / totalWeight;
      if (weightedProgress <= 0.01) {
        setEta("Estimating...");
        return;
      }

      const estimatedTotal = elapsed / weightedProgress;
      const remaining = Math.max(0, estimatedTotal - elapsed);

      if (remaining < 30000) setEta("< 30s");
      else if (remaining < 90000) setEta("~1 min");
      else setEta(`~${Math.round(remaining / 60000)} min`);
    };

    compute();
    const timer = setInterval(compute, 5000); // Re-compute every 5s
    return () => clearInterval(timer);
  }, [scanStartedAt, phaseIdx, aiCalls, maxAiCalls]);

  return eta;
}

export default function ScanProgressPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const logEndRef = useRef<HTMLDivElement>(null);
  const [showCompletion, setShowCompletion] = useState(false);
  const [tick, setTick] = useState(0);

  // Tick for animations
  useEffect(() => {
    const t = setInterval(() => setTick((v) => v + 1), 2000);
    return () => clearInterval(t);
  }, []);

  const [scanDone, setScanDone] = useState(false);

  const { data: scan, refetch } = useQuery<Scan>({
    queryKey: ["scan", scanId],
    queryFn: () => api.get(`/scans/${scanId}`),
    refetchInterval: scanDone ? false : 3000,
  });

  const { data: project } = useQuery<Project>({
    queryKey: ["project", scan?.project_id],
    queryFn: () => api.get(`/projects/${scan!.project_id}`),
    enabled: !!scan?.project_id,
  });

  const { data: persistedEvents } = useQuery<ScanEvent[]>({
    queryKey: ["scan-events", scanId],
    queryFn: () => api.get(`/scans/${scanId}/events?limit=500`),
    enabled: !!scanId,
  });

  const isApk = project?.source_type !== undefined && project.source_type !== "codebase";
  const PHASES = getPhases(isApk);

  const { events, lastProgress } = useWebSocket(scanId);

  // Only auto-scroll the log panel if user is already near the bottom
  const logContainerRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const container = logContainerRef.current;
    if (!container) return;
    const isNearBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 80;
    if (isNearBottom) {
      logEndRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }, [events.length, persistedEvents?.length]);

  useEffect(() => {
    const isComplete =
      scan?.status === "completed" || lastProgress?.status === "completed";
    if (isComplete && !showCompletion) {
      setScanDone(true);
      setShowCompletion(true);
      const timer = setTimeout(() => navigate(`/scan/${scanId}/report`), 3000);
      return () => clearTimeout(timer);
    }
    if (scan?.status === "cancelled" || scan?.status === "failed") {
      setScanDone(true);
      if (scan?.status === "cancelled") {
        const timer = setTimeout(() => navigate("/history"), 2000);
        return () => clearTimeout(timer);
      }
    }
  }, [scan?.status, lastProgress?.status, scanId, navigate, showCompletion]);

  const currentPhase = lastProgress?.phase ?? scan?.current_phase ?? "triage";
  const currentTask = lastProgress?.task ?? scan?.current_task ?? "";
  const filesProcessed = lastProgress?.files_processed ?? scan?.files_processed ?? 0;
  const filesTotal = lastProgress?.files_total ?? scan?.files_total ?? 0;
  const findingsCount = lastProgress?.findings_count ?? scan?.findings_count ?? 0;
  const phaseIdx = PHASES.findIndex((p) => p.id === currentPhase);

  // Use files_processed for better progress estimation during investigation
  const aiCalls = lastProgress?.ai_calls_made ?? scan?.ai_calls_made ?? 0;
  const maxAiCalls = scan?.mode === "heavy" ? 300 : scan?.mode === "light" ? 30 : 100;
  const progressInPhase = phaseIdx === 3 && maxAiCalls > 0 ? aiCalls / maxAiCalls : 0.5;
  const overallProgress = PHASES.length > 0
    ? Math.round(((phaseIdx + progressInPhase) / PHASES.length) * 100)
    : 0;

  const persistedLogEvents = (persistedEvents ?? []).map((event) => ({
    type: "event" as const,
    phase: event.phase ?? undefined,
    level: event.level,
    message: event.message,
    detail: event.detail ?? undefined,
  }));
  const liveLogEvents = events.filter((e) => e.type === "event");
  const logEvents = [...persistedLogEvents, ...liveLogEvents];
  const scannerRuns = [...persistedLogEvents, ...events].reduce((acc, event) => {
    const detail = (event.detail ?? {}) as Record<string, unknown>;
    const scannerRun = detail as Partial<ScannerRunSummary>;
    if (typeof scannerRun.scanner === "string" && typeof scannerRun.status === "string") {
      acc[scannerRun.scanner] = {
        scanner: scannerRun.scanner,
        status: scannerRun.status as ScannerRunSummary["status"],
        success: Boolean(scannerRun.success),
        hit_count: Number(scannerRun.hit_count ?? 0),
        duration_ms: Number(scannerRun.duration_ms ?? 0),
        errors: Array.isArray(scannerRun.errors) ? scannerRun.errors.filter((e): e is string => typeof e === "string") : [],
      };
    }
    if (detail.scanner_runs && typeof detail.scanner_runs === "object") {
      for (const [name, raw] of Object.entries(detail.scanner_runs as Record<string, unknown>)) {
        const run = raw as Partial<ScannerRunSummary>;
        acc[name] = {
          scanner: typeof run.scanner === "string" ? run.scanner : name,
          status: (typeof run.status === "string" ? run.status : "completed") as ScannerRunSummary["status"],
          success: Boolean(run.success),
          hit_count: Number(run.hit_count ?? 0),
          duration_ms: Number(run.duration_ms ?? 0),
          errors: Array.isArray(run.errors) ? run.errors.filter((e): e is string => typeof e === "string") : [],
        };
      }
    }
    return acc;
  }, {} as Record<string, ScannerRunSummary>);
  const progressDetail = (lastProgress?.detail ?? {}) as Record<string, unknown>;
  const degradedCoverage = Boolean(progressDetail.degraded_coverage);
  const ignoredFileCount = Number(progressDetail.ignored_file_count ?? 0);
  const eta = useETA(scan?.started_at ?? null, phaseIdx, PHASES.length, aiCalls, maxAiCalls);

  // Elapsed time
  const elapsed = scan?.started_at
    ? Math.floor((Date.now() - new Date(scan.started_at).getTime()) / 1000)
    : 0;
  const elapsedStr = elapsed > 0
    ? elapsed < 60
      ? `${elapsed}s`
      : `${Math.floor(elapsed / 60)}m ${elapsed % 60}s`
    : "—";

  /* ── Completion overlay ─────────────────────────────────────── */
  if (showCompletion) {
    return (
      <div className="flex items-center justify-center min-h-[70vh]">
        <div className="text-center space-y-6">
          <div className="relative inline-block">
            <div
              className="absolute inset-0 rounded-full blur-3xl opacity-20"
              style={{ background: "linear-gradient(135deg, #00d4ff, #64ffda, #00C851)" }}
            />
            <CheckCircle2 className="relative w-24 h-24 text-accent-success" />
          </div>
          <div>
            <h1 className="text-3xl font-bold text-gradient">Scan Complete</h1>
            <p className="text-text-secondary mt-2">
              {findingsCount} finding{findingsCount !== 1 ? "s" : ""} identified
              across {filesProcessed} files
            </p>
          </div>
          <a
            href={`/scan/${scanId}/report`}
            onClick={(e) => { e.preventDefault(); navigate(`/scan/${scanId}/report`); }}
            className="flex items-center justify-center gap-2 text-accent-primary hover:text-accent-primary/80 cursor-pointer"
          >
            <span className="text-sm font-medium">View Report</span>
            <ArrowRight className="w-4 h-4" />
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ── Header ────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="relative">
            <img
              src="/logo.png"
              alt=""
              className="w-12 h-12 rounded-xl object-cover shadow-lg shadow-accent-primary/10"
            />
            {scan?.status === "running" && (
              <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-accent-primary pulse-dot" />
            )}
          </div>
          <div>
            <h1 className="text-2xl font-bold">
              {scan?.status === "failed" ? "Scan Failed" : scan?.status === "cancelled" ? "Scan Cancelled" : "Scanning..."}
            </h1>
            <p className="text-text-secondary text-sm mt-0.5 flex items-center gap-2">
              {isApk && (
                <span className="text-[10px] uppercase tracking-wider text-accent-purple bg-accent-purple/10 px-2 py-0.5 rounded-full font-medium">
                  APK
                </span>
              )}
              {scan?.mode?.toUpperCase()} mode
              {scan?.started_at && (
                <span className="ml-2 text-text-muted">
                  started {new Date(scan.started_at).toLocaleTimeString()}
                </span>
              )}
            </p>
          </div>
        </div>

        {scan?.status === "running" && (
          <button
            className="btn-danger flex items-center gap-2"
            onClick={async () => {
              await api.post(`/scans/${scanId}/cancel`);
              refetch();
            }}
          >
            <StopCircle className="w-4 h-4" />
            Cancel Scan
          </button>
        )}
      </div>

      {/* ── Stats Bar with ETA ─────────────────────────────────── */}
      <HudFrame label="scan telemetry" color="accent-primary" className="mt-2">
        <div className="grid grid-cols-5 gap-3 pt-4 pb-3 px-3">
          <MiniStat
            icon={<FileCode2 className="w-4 h-4" />}
            label="Files"
            numValue={filesProcessed}
            suffix={` / ${filesTotal || "—"}`}
            color="primary"
          />
          <MiniStat
            icon={<Bug className="w-4 h-4" />}
            label="Findings"
            numValue={findingsCount}
            color={findingsCount > 0 ? "warning" : "secondary"}
          />
          <MiniStat
            icon={<Activity className="w-4 h-4" />}
            label="Phase"
            textValue={`${phaseIdx + 1}/${PHASES.length}`}
            color="primary"
          />
          <MiniStat
            icon={<Clock className="w-4 h-4" />}
            label="Elapsed"
            textValue={elapsedStr}
            color="secondary"
          />
          <MiniStat
            icon={<Timer className="w-4 h-4" />}
            label="ETA"
            textValue={eta || "—"}
            color="primary"
          />
        </div>
      </HudFrame>

      {/* ── Overall Progress Bar ───────────────────────────────── */}
      <div className="relative">
        <div className="w-full h-2 bg-bg-secondary rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-1000 ease-out relative overflow-hidden"
            style={{
              width: `${Math.max(3, overallProgress)}%`,
              background: `linear-gradient(90deg, ${PHASES[0]?.gradientFrom || "#00d4ff"}, ${PHASES[Math.min(phaseIdx, PHASES.length - 1)]?.gradientTo || "#22c55e"})`,
            }}
          >
            {/* Shimmer effect */}
            <div
              className="absolute inset-0 opacity-30"
              style={{
                background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.4), transparent)",
                animation: "shimmer 2s infinite",
              }}
            />
          </div>
        </div>
        <div className="flex justify-between mt-1.5">
          {PHASES.map((phase, i) => (
            <div
              key={phase.id}
              className={`text-[8px] font-mono ${
                i <= phaseIdx ? "text-text-secondary" : "text-text-muted/40"
              }`}
            >
              {phase.label.split(" ")[0]}
            </div>
          ))}
        </div>
      </div>

      {(Object.keys(scannerRuns).length > 0 || degradedCoverage || ignoredFileCount > 0) && (
        <HudFrame label="scanner health" color={degradedCoverage ? "accent-warning" : "accent-secondary"}>
          <div className="px-3 pt-4 pb-3 space-y-3">
            {degradedCoverage && (
              <div className="rounded-xl border border-accent-warning/20 bg-accent-warning/10 px-3 py-2 text-sm text-accent-warning">
                Scanner coverage is degraded. At least one scanner failed or returned errors.
              </div>
            )}
            {ignoredFileCount > 0 && (
              <div className="rounded-xl border border-border/50 bg-bg-secondary/40 px-3 py-2 text-sm text-text-secondary">
                {ignoredFileCount} files are outside scan scope due to default skips, managed-path exclusions, or <code>.vragentignore</code>.
              </div>
            )}
            {Object.keys(scannerRuns).length > 0 && (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
                {Object.values(scannerRuns).map((run) => {
                  const tone =
                    run.status === "failed"
                      ? "border-accent-danger/30 bg-accent-danger/10 text-accent-danger"
                      : run.status === "degraded"
                      ? "border-accent-warning/30 bg-accent-warning/10 text-accent-warning"
                      : "border-accent-success/20 bg-accent-success/10 text-accent-success";
                  return (
                    <div key={run.scanner} className={`rounded-xl border px-3 py-2 ${tone}`}>
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-semibold uppercase tracking-wide text-[11px]">{run.scanner}</span>
                        <span className="text-[10px] font-mono uppercase">{run.status}</span>
                      </div>
                      <div className="mt-2 flex items-center gap-3 text-xs">
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
          </div>
        </HudFrame>
      )}

      {/* ── Main Layout: Pipeline + Log ───────────────────────── */}
      <div className="grid grid-cols-3 gap-6">
        {/* Pipeline — left 2 cols */}
        <div className="col-span-2 space-y-2">
          {PHASES.map((phase, i) => {
            const isActive = phase.id === currentPhase;
            const isDone = i < phaseIdx;
            const isAllDone = scan?.status === "completed";

            return (
              <div key={phase.id}>
                {/* Phase card */}
                <div
                  className={`relative overflow-hidden rounded-xl border transition-all duration-500 ${
                    isActive
                      ? "border-border bg-bg-card shadow-lg"
                      : isDone || isAllDone
                      ? "border-border/50 bg-bg-card/50 opacity-70"
                      : "border-border/20 bg-bg-secondary/20 opacity-35"
                  }`}
                  style={isActive ? {
                    boxShadow: `0 0 30px ${phase.gradientFrom}10, 0 0 60px ${phase.gradientFrom}05`,
                  } : undefined}
                >
                  {/* Active gradient border left */}
                  {isActive && (
                    <div
                      className="absolute left-0 top-0 bottom-0 w-1"
                      style={{ background: `linear-gradient(180deg, ${phase.gradientFrom}, ${phase.gradientTo})` }}
                    />
                  )}
                  {(isDone || isAllDone) && (
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-accent-success/60" />
                  )}

                  {/* Active scan line animation */}
                  {isActive && (
                    <div
                      className="absolute inset-0 pointer-events-none"
                      style={{
                        background: `linear-gradient(180deg, transparent 0%, ${phase.gradientFrom}08 50%, transparent 100%)`,
                        animation: "scan-line 3s ease-in-out infinite",
                      }}
                    />
                  )}

                  <div className="flex items-start gap-4 p-4 pl-5">
                    {/* Icon with glow */}
                    <div className="relative">
                      <div
                        className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 transition-all duration-300 ${
                          isActive
                            ? `${phase.bgColor}/15 ${phase.color}`
                            : isDone || isAllDone
                            ? "bg-accent-success/10 text-accent-success"
                            : "bg-bg-secondary text-text-muted"
                        }`}
                      >
                        {isActive ? (
                          <Loader2 className="w-5 h-5 animate-spin" />
                        ) : isDone || isAllDone ? (
                          <CheckCircle2 className="w-5 h-5" />
                        ) : (
                          <phase.icon className="w-5 h-5" />
                        )}
                      </div>
                      {/* Glow ring on active */}
                      {isActive && (
                        <div
                          className="absolute -inset-1 rounded-xl opacity-20 blur-sm"
                          style={{ background: phase.gradientFrom }}
                        />
                      )}
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3">
                        <h3
                          className={`font-semibold ${
                            isActive ? phase.color : isDone || isAllDone ? "text-text-primary" : "text-text-muted"
                          }`}
                        >
                          {phase.label}
                        </h3>
                        {isActive && (
                          <span
                            className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full font-medium animate-pulse"
                            style={{
                              background: `${phase.gradientFrom}15`,
                              color: phase.gradientFrom,
                            }}
                          >
                            In Progress
                          </span>
                        )}
                        {(isDone || isAllDone) && (
                          <span className="text-[10px] uppercase tracking-wider text-accent-success bg-accent-success/10 px-2 py-0.5 rounded-full font-medium">
                            Complete
                          </span>
                        )}
                      </div>

                      <p className="text-xs text-text-muted mt-0.5">
                        {phase.description}
                      </p>

                      {/* Substeps */}
                      {(isActive || isDone || isAllDone) && (
                        <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1.5">
                          {phase.substeps.map((step, si) => {
                            const substepDone = isDone || isAllDone;
                            const substepActive = isActive && si <= Math.floor(tick % phase.substeps.length);

                            return (
                              <div key={si} className="flex items-center gap-2 text-xs">
                                {substepDone ? (
                                  <CheckCircle2 className="w-3.5 h-3.5 text-accent-success shrink-0" />
                                ) : substepActive ? (
                                  <div className="relative shrink-0">
                                    <div
                                      className="w-3.5 h-3.5 rounded-full"
                                      style={{ background: `${phase.gradientFrom}60` }}
                                    />
                                    <div
                                      className="absolute inset-0 w-3.5 h-3.5 rounded-full animate-ping opacity-40"
                                      style={{ background: phase.gradientFrom }}
                                    />
                                  </div>
                                ) : (
                                  <div className="w-3.5 h-3.5 rounded-full bg-border/50 shrink-0" />
                                )}
                                <span
                                  className={
                                    substepDone
                                      ? "text-text-secondary"
                                      : substepActive
                                      ? "text-text-primary"
                                      : "text-text-muted/60"
                                  }
                                >
                                  {step}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      )}

                      {/* Current task detail */}
                      {isActive && currentTask && (
                        <div className="mt-3 px-3 py-2 rounded-lg bg-[#0c0c14] border border-[#1a1a2e]">
                          <div className="flex items-center gap-2 text-xs font-mono">
                            <Zap className="w-3 h-3 text-accent-warning shrink-0" />
                            <TypingText
                              text={currentTask}
                              speed={15}
                              className="text-accent-success"
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Connector line */}
                {i < PHASES.length - 1 && (
                  <div className="flex justify-start ml-[2.1rem] py-0.5">
                    <div
                      className={`w-px h-3 transition-all duration-500 ${
                        isDone || isAllDone
                          ? "bg-accent-success/40"
                          : isActive
                          ? "bg-border/60"
                          : "bg-border/20"
                      }`}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Event Log — right col (terminal style) */}
        <div className="col-span-1">
          <div className="terminal sticky top-8 flex flex-col" style={{ maxHeight: "calc(100vh - 12rem)" }}>
            <div className="terminal-header">
              <div className="terminal-dot bg-accent-danger/70" />
              <div className="terminal-dot bg-accent-warning/70" />
              <div className="terminal-dot bg-accent-success/70" />
              <span className="ml-2 text-[10px] font-mono text-text-muted/50">
                vragent — event stream
              </span>
              <span className="ml-auto text-[10px] font-mono text-text-muted/40 tabular-nums">
                {logEvents.length}
              </span>
            </div>

            {filesTotal > 0 && (
              <div className="px-4 pt-2">
                <div className="w-full h-1 bg-[#1a1a2e] rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-accent-success to-accent-primary rounded-full transition-all duration-700 ease-out"
                    style={{
                      width: `${Math.min(100, (filesProcessed / filesTotal) * 100)}%`,
                    }}
                  />
                </div>
              </div>
            )}

            <div
              ref={logContainerRef}
              className="terminal-body flex-1 overflow-y-auto space-y-0.5 pr-1"
              style={{ minHeight: 200 }}
            >
              {logEvents.length === 0 && (
                <div className="flex flex-col items-center justify-center py-12 opacity-40">
                  <Loader2 className="w-6 h-6 animate-spin mb-3 text-accent-success" />
                  <p className="text-xs text-accent-success/50">awaiting stream...</p>
                </div>
              )}
              {logEvents.map((event, i) => (
                <div
                  key={i}
                  className={`py-0.5 leading-relaxed flex gap-1.5 ${
                    event.level === "error"
                      ? "log-error"
                      : event.level === "warn"
                      ? "log-warn"
                      : "log-info"
                  }`}
                >
                  <span className="log-prefix shrink-0 w-[3ch] text-right tabular-nums">
                    {String(i + 1).padStart(3, "0")}
                  </span>
                  <span className="log-prefix shrink-0">|</span>
                  <span className="break-words">{event.message}</span>
                </div>
              ))}
              {logEvents.length > 0 && scan?.status === "running" && (
                <div className="py-0.5 log-info blink-cursor">
                  <span className="log-prefix">{">"}</span>
                </div>
              )}
              <div ref={logEndRef} />
            </div>
          </div>
        </div>
      </div>

      {/* ── Error Banner ──────────────────────────────────────── */}
      {scan?.status === "failed" && scan.error_message && (
        <div className="card-glow border-l-4 border-l-accent-danger">
          <div className="flex items-start gap-3">
            <XCircle className="w-5 h-5 text-accent-danger shrink-0 mt-0.5" />
            <div>
              <h3 className="font-semibold text-accent-danger">Scan Failed</h3>
              <p className="text-sm text-text-secondary mt-1">{scan.error_message}</p>
            </div>
          </div>
        </div>
      )}

      {/* Inline CSS for scan line animation */}
      <style>{`
        @keyframes scan-line {
          0%, 100% { transform: translateY(-100%); }
          50% { transform: translateY(100%); }
        }
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
      `}</style>
    </div>
  );
}

/* ── Mini stat card ───────────────────────────────────────────── */
function MiniStat({
  icon,
  label,
  numValue,
  textValue,
  suffix = "",
  color,
}: {
  icon: React.ReactNode;
  label: string;
  numValue?: number;
  textValue?: string;
  suffix?: string;
  color: "primary" | "secondary" | "warning";
}) {
  const colors = {
    primary: "text-accent-primary",
    secondary: "text-accent-secondary",
    warning: "text-accent-warning",
  };
  return (
    <div className="card-glow py-3 px-4">
      <div className="flex items-center gap-2 mb-1">
        <span className={`opacity-50 ${colors[color]}`}>{icon}</span>
        <span className="mono-label">{label}</span>
      </div>
      <p className={`text-lg font-bold font-mono ${colors[color]}`}>
        {numValue !== undefined ? (
          <>
            <AnimatedCounter value={numValue} />
            {suffix && <span className="text-text-muted text-sm">{suffix}</span>}
          </>
        ) : (
          textValue ?? "—"
        )}
      </p>
    </div>
  );
}
