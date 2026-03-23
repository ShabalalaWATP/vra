const SEVERITIES = ["all", "critical", "high", "medium", "low", "info"] as const;

interface SeverityFilterProps {
  value: string;
  onChange: (severity: string) => void;
  counts?: Record<string, number>;
}

export default function SeverityFilter({
  value,
  onChange,
  counts,
}: SeverityFilterProps) {
  return (
    <div className="flex gap-1.5">
      {SEVERITIES.map((sev) => {
        const count = sev === "all"
          ? undefined
          : counts?.[sev];

        return (
          <button
            key={sev}
            onClick={() => onChange(sev)}
            className={`text-xs px-3 py-1.5 rounded-full transition-colors flex items-center gap-1.5 ${
              value === sev
                ? "bg-accent-primary text-bg-primary font-medium"
                : "bg-bg-secondary text-text-muted hover:text-text-primary hover:bg-bg-hover"
            }`}
          >
            {sev === "all" ? "All" : sev.charAt(0).toUpperCase() + sev.slice(1)}
            {count !== undefined && count > 0 && (
              <span
                className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                  value === sev
                    ? "bg-bg-primary/20"
                    : "bg-bg-tertiary"
                }`}
              >
                {count}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
}
