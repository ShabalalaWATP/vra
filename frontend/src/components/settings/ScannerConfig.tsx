import { useQuery } from "@tanstack/react-query";
import { Check, X, RefreshCw } from "lucide-react";
import { api } from "@/api/client";

interface ToolInfo {
  available: boolean;
  path: string | null;
}

interface ToolsResponse {
  tools: Record<string, ToolInfo>;
}

export default function ScannerConfig() {
  const { data, isLoading, refetch } = useQuery<ToolsResponse>({
    queryKey: ["tools"],
    queryFn: () => api.get("/health/tools"),
  });

  const SCANNER_INFO: Record<string, { name: string; description: string }> = {
    semgrep: {
      name: "Semgrep",
      description: "Multi-language static analysis with custom rule support",
    },
    bandit: {
      name: "Bandit",
      description: "Python-specific security analysis",
    },
    eslint: {
      name: "ESLint",
      description: "JavaScript/TypeScript linting with security rules",
    },
    advisory_db: {
      name: "Advisory Database",
      description: "Offline vulnerability advisories for dependency checking",
    },
    semgrep_rules: {
      name: "Semgrep Rules",
      description: "Local offline Semgrep rule repository",
    },
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">Scanner Availability</h3>
        <button
          className="btn-secondary text-xs flex items-center gap-1"
          onClick={() => refetch()}
          disabled={isLoading}
        >
          <RefreshCw className={`w-3 h-3 ${isLoading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {data ? (
        <div className="space-y-3">
          {Object.entries(data.tools).map(([key, info]) => {
            const meta = SCANNER_INFO[key] || {
              name: key,
              description: "",
            };
            return (
              <div
                key={key}
                className="flex items-center justify-between py-3 border-b border-border/50"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{meta.name}</span>
                    {info.available ? (
                      <Check className="w-4 h-4 text-accent-success" />
                    ) : (
                      <X className="w-4 h-4 text-accent-danger" />
                    )}
                  </div>
                  <p className="text-xs text-text-muted mt-0.5">
                    {meta.description}
                  </p>
                  {info.path && (
                    <p className="text-xs font-mono text-text-muted mt-0.5">
                      {info.path}
                    </p>
                  )}
                </div>
                <span
                  className={`badge ${
                    info.available ? "badge-low" : "badge-critical"
                  }`}
                >
                  {info.available ? "Available" : "Not Found"}
                </span>
              </div>
            );
          })}
        </div>
      ) : isLoading ? (
        <p className="text-text-muted text-sm">Checking scanner availability...</p>
      ) : (
        <p className="text-text-muted text-sm">Failed to check scanners.</p>
      )}

      <div className="bg-bg-tertiary rounded-lg p-4 text-xs text-text-muted space-y-2">
        <p className="font-medium text-text-secondary">Installation Notes</p>
        <p>
          Semgrep:{" "}
          <code className="bg-bg-secondary px-1 rounded">pip install semgrep</code>
        </p>
        <p>
          Bandit:{" "}
          <code className="bg-bg-secondary px-1 rounded">pip install bandit</code>
        </p>
        <p>
          ESLint:{" "}
          <code className="bg-bg-secondary px-1 rounded">cd frontend &amp;&amp; npm ci</code>
        </p>
        <p>
          ESLint is bundled with the frontend dependencies; the scanner will also try to bootstrap it automatically on first use.
        </p>
      </div>
    </div>
  );
}
