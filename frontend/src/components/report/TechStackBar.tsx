interface TechStackBarProps {
  languages: string[];
  frameworks: string[];
}

/**
 * Renders tech stack badges with inline SVG icons loaded from the backend.
 * Icons are served from /api/icons/{name}.svg — fully offline.
 */
export default function TechStackBar({
  languages,
  frameworks,
}: TechStackBarProps) {
  return (
    <div className="flex gap-3 flex-wrap">
      {languages.map((lang) => (
        <TechBadge
          key={lang}
          name={lang}
          variant="language"
        />
      ))}
      {frameworks.map((fw) => (
        <TechBadge
          key={fw}
          name={fw}
          variant="framework"
        />
      ))}
    </div>
  );
}

function TechBadge({
  name,
  variant,
}: {
  name: string;
  variant: "language" | "framework";
}) {
  const iconUrl = `/api/icons/${encodeURIComponent(name.toLowerCase())}.svg`;
  const colorClass =
    variant === "language"
      ? "bg-accent-primary/10 text-accent-primary border-accent-primary/20"
      : "bg-accent-purple/10 text-accent-purple border-accent-purple/20";

  return (
    <span
      className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-sm font-medium ${colorClass}`}
    >
      <img
        src={iconUrl}
        alt=""
        className="w-4 h-4 opacity-80"
        onError={(e) => {
          // Hide broken icon images
          (e.target as HTMLImageElement).style.display = "none";
        }}
      />
      {name}
    </span>
  );
}
