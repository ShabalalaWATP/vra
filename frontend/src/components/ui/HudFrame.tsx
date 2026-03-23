import { ReactNode } from "react";

/**
 * HUD-style tactical frame with corner brackets.
 * Wraps any content in a "heads-up display" container.
 */
export default function HudFrame({
  children,
  className = "",
  label,
  color = "accent-primary",
  animate = false,
}: {
  children: ReactNode;
  className?: string;
  label?: string;
  color?: string;
  animate?: boolean;
}) {
  const textClass = `text-${color}`;

  return (
    <div className={`relative ${className}`}>
      {/* Corner brackets */}
      <Corner position="top-left" color={color} />
      <Corner position="top-right" color={color} />
      <Corner position="bottom-left" color={color} />
      <Corner position="bottom-right" color={color} />

      {/* Optional label */}
      {label && (
        <div className="absolute -top-2.5 left-6 px-2 bg-bg-primary">
          <span
            className={`text-[10px] uppercase tracking-[0.15em] font-mono font-medium ${textClass}`}
          >
            {label}
          </span>
        </div>
      )}

      {/* Animated scan line */}
      {animate && (
        <div className="absolute inset-0 overflow-hidden rounded pointer-events-none">
          <div
            className="absolute left-0 right-0 h-px opacity-30"
            style={{
              background: `linear-gradient(90deg, transparent, var(--tw-colors-${color}, #00d4ff), transparent)`,
              animation: "hud-scan 3s ease-in-out infinite",
            }}
          />
        </div>
      )}

      {/* Content */}
      <div className="relative">{children}</div>
    </div>
  );
}

function Corner({
  position,
  color,
}: {
  position: "top-left" | "top-right" | "bottom-left" | "bottom-right";
  color: string;
}) {
  const size = 12;
  const thickness = 1.5;
  const colorVal =
    color === "accent-primary" ? "#00d4ff" :
    color === "accent-secondary" ? "#64ffda" :
    color === "accent-danger" ? "#ff4444" :
    color === "accent-warning" ? "#ffbb33" :
    color === "accent-purple" ? "#bb86fc" :
    color === "accent-orange" ? "#ff8c00" :
    color === "accent-success" ? "#00C851" :
    "#00d4ff";

  const positions: Record<string, string> = {
    "top-left": "top-0 left-0",
    "top-right": "top-0 right-0",
    "bottom-left": "bottom-0 left-0",
    "bottom-right": "bottom-0 right-0",
  };

  const transforms: Record<string, string> = {
    "top-left": "",
    "top-right": "scale(-1, 1)",
    "bottom-left": "scale(1, -1)",
    "bottom-right": "scale(-1, -1)",
  };

  return (
    <svg
      className={`absolute ${positions[position]} pointer-events-none`}
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      style={{ transform: transforms[position] }}
    >
      <path
        d={`M0,${size} L0,0 L${size},0`}
        fill="none"
        stroke={colorVal}
        strokeWidth={thickness}
        opacity={0.6}
      />
    </svg>
  );
}
