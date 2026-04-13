/**
 * Chart.js-based chart components for the report page.
 * All charts are max-size capped to prevent layout explosion.
 * Dark theme colors throughout.
 */
import {
  Chart as ChartJS,
  ArcElement,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  RadialLinearScale,
  Tooltip,
  Legend,
  Filler,
  type ChartOptions,
} from "chart.js";
import { Doughnut, Bar, Radar, PolarArea } from "react-chartjs-2";
import { useMemo } from "react";

// Register Chart.js components once
ChartJS.register(
  ArcElement,
  CategoryScale,
  LinearScale,
  BarElement,
  PointElement,
  LineElement,
  RadialLinearScale,
  Tooltip,
  Legend,
  Filler
);

// ── Global defaults for dark theme ────────────────────────────
ChartJS.defaults.color = "#8b8fa3";
ChartJS.defaults.borderColor = "rgba(255,255,255,0.06)";
ChartJS.defaults.font.family = "'JetBrains Mono', 'Fira Code', monospace";
ChartJS.defaults.font.size = 11;
ChartJS.defaults.plugins.legend!.labels!.boxWidth = 12;
ChartJS.defaults.plugins.legend!.labels!.padding = 12;
ChartJS.defaults.plugins.tooltip!.backgroundColor = "#1a1a2e";
ChartJS.defaults.plugins.tooltip!.titleColor = "#e2e4f0";
ChartJS.defaults.plugins.tooltip!.bodyColor = "#a0a3b8";
ChartJS.defaults.plugins.tooltip!.borderColor = "rgba(0,212,255,0.2)";
ChartJS.defaults.plugins.tooltip!.borderWidth = 1;
ChartJS.defaults.plugins.tooltip!.cornerRadius = 8;
ChartJS.defaults.plugins.tooltip!.padding = 10;

// ── Color palettes ────────────────────────────────────────────
const SEV_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#06b6d4",
};

const SCANNER_COLORS: Record<string, string> = {
  semgrep: "#06b6d4",
  bandit: "#f59e0b",
  eslint: "#8b5cf6",
  codeql: "#ec4899",
  secrets: "#ef4444",
  dep_audit: "#22c55e",
};

const FINDING_SOURCE_COLORS: Record<string, string> = {
  scanner: "#06b6d4",
  llm: "#f59e0b",
  hybrid: "#ec4899",
};

const VERIFICATION_COLORS: Record<string, string> = {
  hypothesis: "#6b7280",
  statically_verified: "#3b82f6",
  strongly_verified: "#22c55e",
  runtime_validated: "#ef4444",
};

const LANG_COLORS: Record<string, string> = {
  python: "#3572A5",
  javascript: "#f1e05a",
  typescript: "#3178c6",
  java: "#b07219",
  kotlin: "#A97BFF",
  go: "#00ADD8",
  rust: "#dea584",
  ruby: "#701516",
  php: "#4F5D95",
  csharp: "#178600",
  c: "#555555",
  cpp: "#f34b7d",
  swift: "#F05138",
  html: "#e34c26",
  css: "#563d7c",
  shell: "#89e051",
  sql: "#e38c00",
  vue: "#41b883",
  dart: "#00B4AB",
  scala: "#c22d40",
};

const CATEGORY_COLORS = [
  "#06b6d4", "#f59e0b", "#8b5cf6", "#ec4899", "#22c55e",
  "#ef4444", "#3b82f6", "#f97316", "#14b8a6", "#a855f7",
];

// ── Wrapper to enforce max size ───────────────────────────────
function ChartContainer({
  children,
  title,
  maxWidth,
  maxHeight,
  className = "",
}: {
  children: React.ReactNode;
  title?: string;
  maxWidth?: number;
  maxHeight?: number;
  className?: string;
}) {
  return (
    <div className={`flex flex-col items-center w-full ${className}`}>
      {title && (
        <p className="text-[10px] text-text-muted uppercase tracking-wider mb-3 font-medium">
          {title}
        </p>
      )}
      <div
        className="w-full relative"
        style={{
          maxWidth: maxWidth || undefined,
          maxHeight: maxHeight || undefined,
          minHeight: 200,
        }}
      >
        {children}
      </div>
    </div>
  );
}

// ── 1. Severity Breakdown Donut ───────────────────────────────
export function SeverityDonut({
  counts,
  size = 220,
}: {
  counts: Record<string, number>;
  size?: number;
}) {
  const data = useMemo(() => {
    const entries = Object.entries(counts).filter(([, v]) => v > 0);
    if (!entries.length) return null;

    return {
      labels: entries.map(([sev]) => sev.charAt(0).toUpperCase() + sev.slice(1)),
      datasets: [
        {
          data: entries.map(([, v]) => v),
          backgroundColor: entries.map(([sev]) => SEV_COLORS[sev] || "#6b7280"),
          borderColor: "rgba(0,0,0,0.3)",
          borderWidth: 2,
          hoverBorderColor: "#fff",
          hoverBorderWidth: 2,
          spacing: 2,
        },
      ],
    };
  }, [counts]);

  if (!data) return null;

  const total = Object.values(counts).reduce((a, b) => a + b, 0);

  const options: ChartOptions<"doughnut"> = {
    responsive: true,
    maintainAspectRatio: true,
    cutout: "65%",
    plugins: {
      legend: {
        position: "bottom",
        labels: { usePointStyle: true, pointStyle: "circle" },
      },
      tooltip: {
        callbacks: {
          label: (ctx) => ` ${ctx.label}: ${ctx.parsed} (${Math.round((ctx.parsed / total) * 100)}%)`,
        },
      },
    },
  };

  return (
    <ChartContainer title="Severity Breakdown" maxWidth={size} maxHeight={size + 60}>
      <div className="relative">
        <Doughnut data={data} options={options} />
        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none" style={{ paddingBottom: 40 }}>
          <span className="text-2xl font-bold text-text-primary">{total}</span>
          <span className="text-[10px] text-text-muted">findings</span>
        </div>
      </div>
    </ChartContainer>
  );
}

// ── 2. Scanner Hits Horizontal Bar ────────────────────────────
export function ScannerHitsChart({
  hitCounts,
  maxWidth = 400,
}: {
  hitCounts: Record<string, number>;
  maxWidth?: number;
}) {
  const data = useMemo(() => {
    const entries = Object.entries(hitCounts)
      .filter(([k, v]) => v > 0 && !k.endsWith("_targeted"))
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8);

    if (!entries.length) return null;

    return {
      labels: entries.map(([s]) =>
        s.replace("_", " ").replace(/\b\w/g, (c) => c.toUpperCase())
      ),
      datasets: [
        {
          data: entries.map(([, v]) => v),
          backgroundColor: entries.map(([s]) => {
            const base = SCANNER_COLORS[s] || "#6b7280";
            return base + "cc"; // slight transparency
          }),
          borderColor: entries.map(([s]) => SCANNER_COLORS[s] || "#6b7280"),
          borderWidth: 1,
          borderRadius: 4,
          barThickness: 22,
        },
      ],
    };
  }, [hitCounts]);

  if (!data) return null;

  const options: ChartOptions<"bar"> = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
    },
    scales: {
      x: {
        grid: { color: "rgba(255,255,255,0.04)" },
        ticks: { precision: 0 },
      },
      y: {
        grid: { display: false },
      },
    },
  };

  const height = Math.max(140, data.labels.length * 36 + 30);

  return (
    <ChartContainer title="Raw Scanner Leads" maxWidth={maxWidth} maxHeight={300}>
      <div style={{ height: Math.min(height, 280) }}>
        <Bar data={data} options={options} />
      </div>
    </ChartContainer>
  );
}

export function FindingSourceChart({
  counts,
  maxWidth = 400,
}: {
  counts: Record<string, number>;
  maxWidth?: number;
}) {
  const data = useMemo(() => {
    const ordered = [
      ["Scanner-led", "scanner", counts.scanner || 0],
      ["LLM-only", "llm", counts.llm || 0],
      ["Hybrid", "hybrid", counts.hybrid || 0],
    ] as Array<[string, string, number]>;
    const filtered = ordered.filter(([, , value]) => value > 0);

    if (!filtered.length) return null;

    return {
      labels: filtered.map(([label]) => label),
      datasets: [
        {
          data: filtered.map(([, , value]) => value),
          backgroundColor: filtered.map(([, key]) => (FINDING_SOURCE_COLORS[key] || "#6b7280") + "cc"),
          borderColor: filtered.map(([, key]) => FINDING_SOURCE_COLORS[key] || "#6b7280"),
          borderWidth: 1,
          borderRadius: 4,
          barThickness: 22,
        },
      ],
    };
  }, [counts]);

  if (!data) return null;

  const options: ChartOptions<"bar"> = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
    },
    scales: {
      x: {
        grid: { color: "rgba(255,255,255,0.04)" },
        ticks: { precision: 0 },
      },
      y: {
        grid: { display: false },
      },
    },
  };

  const height = Math.max(140, data.labels.length * 36 + 30);

  return (
    <ChartContainer title="Final Finding Sources" maxWidth={maxWidth} maxHeight={300}>
      <div style={{ height: Math.min(height, 220) }}>
        <Bar data={data} options={options} />
      </div>
    </ChartContainer>
  );
}

export function VerificationLevelChart({
  counts,
  maxWidth = 400,
}: {
  counts: Record<string, number>;
  maxWidth?: number;
}) {
  const data = useMemo(() => {
    const ordered = [
      ["Hypothesis", "hypothesis", counts.hypothesis || 0],
      ["Static", "statically_verified", counts.statically_verified || 0],
      ["Strong", "strongly_verified", counts.strongly_verified || 0],
      ["Runtime", "runtime_validated", counts.runtime_validated || 0],
    ] as Array<[string, string, number]>;
    const filtered = ordered.filter(([, , value]) => value > 0);

    if (!filtered.length) return null;

    return {
      labels: filtered.map(([label]) => label),
      datasets: [
        {
          data: filtered.map(([, , value]) => value),
          backgroundColor: filtered.map(([, key]) => (VERIFICATION_COLORS[key] || "#6b7280") + "cc"),
          borderColor: filtered.map(([, key]) => VERIFICATION_COLORS[key] || "#6b7280"),
          borderWidth: 1,
          borderRadius: 4,
          barThickness: 22,
        },
      ],
    };
  }, [counts]);

  if (!data) return null;

  const options: ChartOptions<"bar"> = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
    },
    scales: {
      x: {
        grid: { color: "rgba(255,255,255,0.04)" },
        ticks: { precision: 0 },
      },
      y: {
        grid: { display: false },
      },
    },
  };

  const height = Math.max(140, data.labels.length * 36 + 30);

  return (
    <ChartContainer title="Verification Levels" maxWidth={maxWidth} maxHeight={300}>
      <div style={{ height: Math.min(height, 240) }}>
        <Bar data={data} options={options} />
      </div>
    </ChartContainer>
  );
}

// ── 3. Language Distribution Polar Area ───────────────────────
export function LanguageChart({
  languages,
  size = 240,
}: {
  languages: Array<{ name: string; file_count: number; percentage?: number }>;
  size?: number;
}) {
  const data = useMemo(() => {
    const top = languages.slice(0, 8);
    if (!top.length) return null;

    return {
      labels: top.map((l) => l.name.charAt(0).toUpperCase() + l.name.slice(1)),
      datasets: [
        {
          data: top.map((l) => l.file_count),
          backgroundColor: top.map((l) => {
            const c = LANG_COLORS[l.name.toLowerCase()] || "#6b7280";
            return c + "99";
          }),
          borderColor: top.map((l) => LANG_COLORS[l.name.toLowerCase()] || "#6b7280"),
          borderWidth: 2,
        },
      ],
    };
  }, [languages]);

  if (!data) return null;

  const options: ChartOptions<"polarArea"> = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: {
      legend: {
        position: "bottom",
        labels: { usePointStyle: true, pointStyle: "circle", font: { size: 10 } },
      },
    },
    scales: {
      r: {
        grid: { color: "rgba(255,255,255,0.06)" },
        ticks: { display: false },
      },
    },
  };

  return (
    <ChartContainer title="Language Distribution" maxWidth={size} maxHeight={size + 60}>
      <PolarArea data={data} options={options} />
    </ChartContainer>
  );
}

// ── 4. Finding Category Bar Chart ─────────────────────────────
export function CategoryChart({
  categories,
  maxWidth = 400,
}: {
  categories: Record<string, number>;
  maxWidth?: number;
}) {
  const data = useMemo(() => {
    const entries = Object.entries(categories)
      .filter(([, v]) => v > 0)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    if (!entries.length) return null;

    return {
      labels: entries.map(([cat]) =>
        cat.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
      ),
      datasets: [
        {
          data: entries.map(([, v]) => v),
          backgroundColor: entries.map((_, i) => CATEGORY_COLORS[i % CATEGORY_COLORS.length] + "aa"),
          borderColor: entries.map((_, i) => CATEGORY_COLORS[i % CATEGORY_COLORS.length]),
          borderWidth: 1,
          borderRadius: 4,
          barThickness: 20,
        },
      ],
    };
  }, [categories]);

  if (!data) return null;

  const options: ChartOptions<"bar"> = {
    indexAxis: "y",
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
    scales: {
      x: {
        grid: { color: "rgba(255,255,255,0.04)" },
        ticks: { precision: 0 },
      },
      y: {
        grid: { display: false },
        ticks: { font: { size: 10 } },
      },
    },
  };

  const height = Math.max(140, data.labels.length * 32 + 30);

  return (
    <ChartContainer title="Finding Categories" maxWidth={maxWidth} maxHeight={300}>
      <div style={{ height: Math.min(height, 280) }}>
        <Bar data={data} options={options} />
      </div>
    </ChartContainer>
  );
}

// ── 5. Confidence Distribution Donut ──────────────────────────
export function ConfidenceDistribution({
  findings,
  size = 200,
}: {
  findings: Array<{ confidence: number }>;
  size?: number;
}) {
  const data = useMemo(() => {
    if (!findings?.length) return null;

    const buckets = { "90-100%": 0, "70-89%": 0, "50-69%": 0, "<50%": 0 };
    const colors = { "90-100%": "#ef4444", "70-89%": "#f97316", "50-69%": "#eab308", "<50%": "#22c55e" };

    findings.forEach((f) => {
      const pct = f.confidence * 100;
      if (pct >= 90) buckets["90-100%"]++;
      else if (pct >= 70) buckets["70-89%"]++;
      else if (pct >= 50) buckets["50-69%"]++;
      else buckets["<50%"]++;
    });

    const entries = Object.entries(buckets).filter(([, v]) => v > 0);
    if (!entries.length) return null;

    return {
      labels: entries.map(([k]) => k),
      datasets: [
        {
          data: entries.map(([, v]) => v),
          backgroundColor: entries.map(([k]) => (colors as any)[k] + "bb"),
          borderColor: entries.map(([k]) => (colors as any)[k]),
          borderWidth: 2,
          spacing: 2,
        },
      ],
    };
  }, [findings]);

  if (!data) return null;

  const options: ChartOptions<"doughnut"> = {
    responsive: true,
    maintainAspectRatio: true,
    cutout: "60%",
    plugins: {
      legend: {
        position: "bottom",
        labels: { usePointStyle: true, pointStyle: "circle", font: { size: 10 } },
      },
    },
  };

  return (
    <ChartContainer title="Confidence Distribution" maxWidth={size} maxHeight={size + 60}>
      <Doughnut data={data} options={options} />
    </ChartContainer>
  );
}

// ── 6. Attack Surface Radar ───────────────────────────────────
export function AttackSurfaceRadar({
  metrics,
  size = 260,
}: {
  metrics: Record<string, number>;
  size?: number;
}) {
  const data = useMemo(() => {
    const entries = Object.entries(metrics).filter(([, v]) => v > 0);
    if (entries.length < 3) return null; // radar needs at least 3 axes

    const maxVal = Math.max(...entries.map(([, v]) => v));

    return {
      labels: entries.map(([k]) =>
        k.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
      ),
      datasets: [
        {
          label: "Attack Surface",
          data: entries.map(([, v]) => Math.round((v / maxVal) * 100)),
          backgroundColor: "rgba(6, 182, 212, 0.15)",
          borderColor: "#06b6d4",
          borderWidth: 2,
          pointBackgroundColor: "#06b6d4",
          pointBorderColor: "#0c0c14",
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
        },
      ],
    };
  }, [metrics]);

  if (!data) return null;

  const options: ChartOptions<"radar"> = {
    responsive: true,
    maintainAspectRatio: true,
    plugins: { legend: { display: false } },
    scales: {
      r: {
        angleLines: { color: "rgba(255,255,255,0.08)" },
        grid: { color: "rgba(255,255,255,0.06)" },
        pointLabels: { color: "#8b8fa3", font: { size: 10 } },
        ticks: { display: false },
        suggestedMin: 0,
        suggestedMax: 100,
      },
    },
  };

  return (
    <ChartContainer title="Attack Surface" maxWidth={size} maxHeight={size + 20}>
      <Radar data={data} options={options} />
    </ChartContainer>
  );
}

// ── 7. Dependency Risk Donut ──────────────────────────────────
export function DependencyRiskDonut({
  depFindings,
  size = 200,
}: {
  depFindings: Array<{
    severity?: string | null;
    reachability_status?: string | null;
    risk_score?: number | null;
  }>;
  size?: number;
}) {
  const chartState = useMemo(() => {
    if (!depFindings?.length) return null;

    const hasReachability = depFindings.some(
      (d) => d.reachability_status && d.reachability_status !== "unknown"
    );
    const counts: Record<string, number> = {};

    if (hasReachability) {
      depFindings.forEach((d) => {
        const status = d.reachability_status || "unknown";
        counts[status] = (counts[status] || 0) + 1;
      });

      const labels: Record<string, string> = {
        reachable: "Reachable",
        potentially_reachable: "Potential",
        no_path_found: "No path",
        not_applicable: "Not applicable",
        unknown: "Unknown",
      };
      const colors: Record<string, string> = {
        reachable: "#ef4444",
        potentially_reachable: "#f97316",
        no_path_found: "#06b6d4",
        not_applicable: "#22c55e",
        unknown: "#6b7280",
      };

      const entries = Object.entries(counts).filter(([, v]) => v > 0);
      if (!entries.length) return null;

      return {
        title: "Dependency Reachability",
        centerLabel: "packages",
        data: {
          labels: entries.map(([status]) => labels[status] || status),
          datasets: [
            {
              data: entries.map(([, v]) => v),
              backgroundColor: entries.map(([status]) => (colors[status] || "#6b7280") + "bb"),
              borderColor: entries.map(([status]) => colors[status] || "#6b7280"),
              borderWidth: 2,
              spacing: 2,
            },
          ],
        },
      };
    }

    depFindings.forEach((d) => {
      const sev = d.severity || "unknown";
      counts[sev] = (counts[sev] || 0) + 1;
    });
    const entries = Object.entries(counts).filter(([, v]) => v > 0);
    if (!entries.length) return null;

    return {
      title: "Dependency Severity",
      centerLabel: "vulns",
      data: {
        labels: entries.map(([s]) => s.charAt(0).toUpperCase() + s.slice(1)),
        datasets: [
          {
            data: entries.map(([, v]) => v),
            backgroundColor: entries.map(([s]) => (SEV_COLORS[s] || "#6b7280") + "bb"),
            borderColor: entries.map(([s]) => SEV_COLORS[s] || "#6b7280"),
            borderWidth: 2,
            spacing: 2,
          },
        ],
      },
    };
  }, [depFindings]);

  if (!chartState) return null;

  const total = depFindings.length;

  const options: ChartOptions<"doughnut"> = {
    responsive: true,
    maintainAspectRatio: true,
    cutout: "60%",
    plugins: {
      legend: {
        position: "bottom",
        labels: { usePointStyle: true, pointStyle: "circle", font: { size: 10 } },
      },
    },
  };

  return (
    <ChartContainer title={chartState.title} maxWidth={size} maxHeight={size + 60}>
      <div className="relative">
        <Doughnut data={chartState.data} options={options} />
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none" style={{ paddingBottom: 40 }}>
          <span className="text-xl font-bold text-text-primary">{total}</span>
          <span className="text-[9px] text-text-muted">{chartState.centerLabel}</span>
        </div>
      </div>
    </ChartContainer>
  );
}
