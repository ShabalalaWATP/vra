import PhaseIndicator from "./PhaseIndicator";
import EventLog from "./EventLog";
import StatsBar from "./StatsBar";
import type { WSEvent, Scan } from "@/types";

interface ScanProgressProps {
  scan: Scan | undefined;
  events: WSEvent[];
  lastProgress: WSEvent | null;
}

export default function ScanProgress({
  scan,
  events,
  lastProgress,
}: ScanProgressProps) {
  const currentPhase = lastProgress?.phase ?? scan?.current_phase ?? "triage";
  const filesProcessed = lastProgress?.files_processed ?? 0;
  const filesTotal = lastProgress?.files_total ?? 0;
  const findingsCount = lastProgress?.findings_count ?? 0;

  const stats = [
    {
      label: "Files Processed",
      value: `${filesProcessed}/${filesTotal || "?"}`,
    },
    { label: "Findings", value: String(findingsCount) },
    { label: "Phase", value: currentPhase },
    {
      label: "Status",
      value: scan?.status ?? "...",
      highlight: scan?.status === "running",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Phase Indicator */}
      <div className="card">
        <PhaseIndicator currentPhase={currentPhase} />
      </div>

      {/* Stats */}
      <StatsBar stats={stats} />

      {/* Main Content */}
      <div className="grid grid-cols-5 gap-6">
        {/* Current Activity */}
        <div className="col-span-3 card space-y-4">
          <h3 className="font-semibold">Current Activity</h3>
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm">
              <span className="text-text-muted w-20">Phase:</span>
              <span className="text-accent-primary font-medium">
                {currentPhase}
              </span>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className="text-text-muted w-20">Task:</span>
              <span className="text-text-primary">
                {scan?.current_task ?? "—"}
              </span>
            </div>
          </div>

          {/* Progress Bar */}
          {filesTotal > 0 && (
            <div className="space-y-1">
              <div className="flex justify-between text-xs text-text-muted">
                <span>File progress</span>
                <span>
                  {Math.round((filesProcessed / filesTotal) * 100)}%
                </span>
              </div>
              <div className="w-full h-2 bg-bg-secondary rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-accent-primary to-accent-secondary rounded-full transition-all duration-500 ease-out"
                  style={{
                    width: `${Math.min(
                      100,
                      (filesProcessed / filesTotal) * 100
                    )}%`,
                  }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Event Log */}
        <div className="col-span-2 card">
          <h3 className="font-semibold mb-3">Event Log</h3>
          <EventLog events={events} maxHeight="350px" />
        </div>
      </div>
    </div>
  );
}
