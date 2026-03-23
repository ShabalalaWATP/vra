import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  Trash2,
  FileText,
  Play,
  Clock,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Search,
  Filter,
} from "lucide-react";
import { useState } from "react";
import { api } from "@/api/client";
import type { Scan } from "@/types";

type StatusFilter = "all" | "completed" | "running" | "failed" | "cancelled" | "pending";

export default function HistoryPage() {
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState<StatusFilter>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const { data: scans, isError, isLoading } = useQuery<Scan[]>({
    queryKey: ["scans"],
    queryFn: () => api.get("/scans"),
  });

  const deleteMutation = useMutation({
    mutationFn: (scanId: string) => api.delete(`/scans/${scanId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setConfirmDeleteId(null);
      setDeletingId(null);
    },
    onError: () => {
      setDeletingId(null);
    },
  });

  const handleDelete = (scanId: string) => {
    setDeletingId(scanId);
    deleteMutation.mutate(scanId);
  };

  // Filter and search
  const filtered = scans?.filter((s) => {
    if (filter !== "all" && s.status !== filter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        s.id.toLowerCase().includes(q) ||
        s.mode.toLowerCase().includes(q) ||
        s.status.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Status counts
  const statusCounts: Record<string, number> = {};
  scans?.forEach((s) => {
    statusCounts[s.status] = (statusCounts[s.status] || 0) + 1;
  });

  if (isError) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertTriangle className="w-10 h-10 text-accent-warning mx-auto mb-3 opacity-50" />
          <p className="text-text-secondary">Failed to load scan history. Is the backend running?</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-6 h-6 text-accent-primary animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scan History</h1>
          <p className="text-text-secondary text-sm mt-1">
            {scans?.length ?? 0} scans total
          </p>
        </div>
        <Link to="/scan/new" className="btn-primary">
          New Scan
        </Link>
      </div>

      {/* Filters bar */}
      <div className="flex items-center gap-4">
        {/* Search */}
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input
            type="text"
            placeholder="Search scans..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:ring-1 focus:ring-accent-primary"
          />
        </div>

        {/* Status filter pills */}
        <div className="flex gap-1">
          {(["all", "completed", "running", "failed", "cancelled", "pending"] as StatusFilter[]).map((s) => {
            const count = s === "all" ? scans?.length : statusCounts[s] || 0;
            if (s !== "all" && !count) return null;
            return (
              <button
                key={s}
                onClick={() => setFilter(s)}
                className={`text-xs px-3 py-1.5 rounded-lg transition-all ${
                  filter === s
                    ? "bg-accent-primary text-bg-primary font-medium"
                    : "bg-bg-tertiary text-text-muted hover:text-text-primary hover:bg-bg-hover"
                }`}
              >
                {s === "all" ? "All" : s.charAt(0).toUpperCase() + s.slice(1)}
                {count ? ` (${count})` : ""}
              </button>
            );
          })}
        </div>
      </div>

      {/* Scan list */}
      {filtered?.length ? (
        <div className="space-y-2">
          {filtered.map((scan) => (
            <ScanCard
              key={scan.id}
              scan={scan}
              isDeleting={deletingId === scan.id}
              isConfirmingDelete={confirmDeleteId === scan.id}
              onConfirmDelete={() => setConfirmDeleteId(scan.id)}
              onCancelDelete={() => setConfirmDeleteId(null)}
              onDelete={() => handleDelete(scan.id)}
            />
          ))}
        </div>
      ) : (
        <div className="card-glow text-center py-16">
          <Filter className="w-10 h-10 text-text-muted mx-auto mb-3 opacity-30" />
          <p className="text-text-muted text-sm">
            {scans?.length ? "No scans match your filter." : "No scans yet. Start your first scan."}
          </p>
        </div>
      )}
    </div>
  );
}

/* ── Scan Card ─────────────────────────────────────────────────── */

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; color: string; bg: string }> = {
  completed: { icon: CheckCircle2, color: "text-accent-success", bg: "bg-accent-success/10" },
  running: { icon: Loader2, color: "text-accent-primary", bg: "bg-accent-primary/10" },
  failed: { icon: XCircle, color: "text-accent-danger", bg: "bg-accent-danger/10" },
  cancelled: { icon: XCircle, color: "text-accent-warning", bg: "bg-accent-warning/10" },
  pending: { icon: Clock, color: "text-text-muted", bg: "bg-bg-secondary" },
};

const MODE_COLORS: Record<string, string> = {
  light: "bg-accent-success/10 text-accent-success border-accent-success/20",
  regular: "bg-accent-primary/10 text-accent-primary border-accent-primary/20",
  heavy: "bg-accent-danger/10 text-accent-danger border-accent-danger/20",
};

function ScanCard({
  scan,
  isDeleting,
  isConfirmingDelete,
  onConfirmDelete,
  onCancelDelete,
  onDelete,
}: {
  scan: Scan;
  isDeleting: boolean;
  isConfirmingDelete: boolean;
  onConfirmDelete: () => void;
  onCancelDelete: () => void;
  onDelete: () => void;
}) {
  const cfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending;
  const StatusIcon = cfg.icon;
  const modeClass = MODE_COLORS[scan.mode] || MODE_COLORS.regular;

  const duration = scan.started_at && scan.completed_at
    ? formatDuration(new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime())
    : null;

  const linkTo =
    scan.status === "running"
      ? `/scan/${scan.id}/progress`
      : scan.status === "completed"
      ? `/scan/${scan.id}/report`
      : null;

  return (
    <div className="card-glow group hover:border-accent-primary/30 transition-all">
      <div className="flex items-center gap-4">
        {/* Status icon */}
        <div className={`w-10 h-10 rounded-xl ${cfg.bg} flex items-center justify-center shrink-0`}>
          <StatusIcon className={`w-5 h-5 ${cfg.color} ${scan.status === "running" ? "animate-spin" : ""}`} />
        </div>

        {/* Main info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3">
            {linkTo ? (
              <Link to={linkTo} className="font-medium hover:text-accent-primary transition-colors">
                Scan {scan.id.slice(0, 8)}
              </Link>
            ) : (
              <span className="font-medium text-text-secondary">Scan {scan.id.slice(0, 8)}</span>
            )}
            <span className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${modeClass}`}>
              {scan.mode}
            </span>
            <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${cfg.bg} ${cfg.color}`}>
              {scan.status}
            </span>
          </div>
          <div className="flex items-center gap-4 mt-1 text-xs text-text-muted">
            {scan.started_at && (
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {new Date(scan.started_at).toLocaleString()}
              </span>
            )}
            {duration && (
              <span>Duration: {duration}</span>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2 shrink-0">
          {linkTo && (
            <Link
              to={linkTo}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary/10 text-accent-primary text-xs font-medium hover:bg-accent-primary/20 transition-colors"
            >
              {scan.status === "running" ? (
                <>
                  <Play className="w-3 h-3" />
                  Progress
                </>
              ) : (
                <>
                  <FileText className="w-3 h-3" />
                  Report
                </>
              )}
            </Link>
          )}

          {/* Delete */}
          {scan.status !== "running" && (
            <>
              {isConfirmingDelete ? (
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-accent-danger">Delete?</span>
                  <button
                    onClick={onDelete}
                    disabled={isDeleting}
                    className="px-2 py-1 rounded bg-accent-danger/20 text-accent-danger text-[10px] font-medium hover:bg-accent-danger/30 transition-colors"
                  >
                    {isDeleting ? (
                      <Loader2 className="w-3 h-3 animate-spin" />
                    ) : (
                      "Yes"
                    )}
                  </button>
                  <button
                    onClick={onCancelDelete}
                    className="px-2 py-1 rounded bg-bg-secondary text-text-muted text-[10px] hover:bg-bg-hover transition-colors"
                  >
                    No
                  </button>
                </div>
              ) : (
                <button
                  onClick={onConfirmDelete}
                  className="p-1.5 rounded-lg text-text-muted hover:text-accent-danger hover:bg-accent-danger/10 transition-colors opacity-0 group-hover:opacity-100"
                  title="Delete scan"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (minutes < 60) return `${minutes}m ${secs}s`;
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  return `${hours}h ${mins}m`;
}
