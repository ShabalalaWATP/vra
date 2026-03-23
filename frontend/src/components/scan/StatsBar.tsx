interface StatItem {
  label: string;
  value: string | number;
  highlight?: boolean;
}

interface StatsBarProps {
  stats: StatItem[];
}

export default function StatsBar({ stats }: StatsBarProps) {
  return (
    <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(${stats.length}, 1fr)` }}>
      {stats.map((stat) => (
        <div key={stat.label} className="card py-4">
          <p className="text-xs text-text-muted uppercase tracking-wide">
            {stat.label}
          </p>
          <p
            className={`text-xl font-bold mt-1 ${
              stat.highlight ? "text-accent-primary" : ""
            }`}
          >
            {stat.value}
          </p>
        </div>
      ))}
    </div>
  );
}
