import {
  Search,
  Brain,
  Bug,
  CheckCircle2,
  FileText,
  Loader2,
} from "lucide-react";

interface Phase {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const PHASES: Phase[] = [
  { id: "triage", label: "Triage", icon: Search },
  { id: "understanding", label: "Understand", icon: Brain },
  { id: "investigation", label: "Investigate", icon: Bug },
  { id: "verification", label: "Verify", icon: CheckCircle2 },
  { id: "reporting", label: "Report", icon: FileText },
];

interface PhaseIndicatorProps {
  currentPhase: string;
}

export default function PhaseIndicator({ currentPhase }: PhaseIndicatorProps) {
  const currentIdx = PHASES.findIndex((p) => p.id === currentPhase);

  return (
    <div className="flex items-center justify-between">
      {PHASES.map((phase, i) => {
        const isActive = phase.id === currentPhase;
        const isDone = i < currentIdx;
        const Icon = phase.icon;

        return (
          <div key={phase.id} className="flex items-center flex-1">
            <div
              className={`flex items-center gap-2 px-3 py-2 rounded-lg transition-all ${
                isActive
                  ? "bg-accent-primary/10 text-accent-primary"
                  : isDone
                  ? "text-accent-success"
                  : "text-text-muted"
              }`}
            >
              {isActive ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : isDone ? (
                <CheckCircle2 className="w-4 h-4" />
              ) : (
                <Icon className="w-4 h-4" />
              )}
              <span className="text-sm font-medium whitespace-nowrap">
                {phase.label}
              </span>
            </div>
            {i < PHASES.length - 1 && (
              <div
                className={`flex-1 h-px mx-2 ${
                  isDone ? "bg-accent-success" : "bg-border"
                }`}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
