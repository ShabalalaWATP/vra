/**
 * MermaidDiagram Component
 *
 * Renders Mermaid diagrams with icon support. Mermaid's built-in fa:icon
 * syntax doesn't reliably render icons in all diagram types, so we
 * post-process the rendered SVG to replace "prefix:icon-name" text with
 * actual inline SVG icons from the Iconify icon packs.
 */

import { useEffect, useRef, useState } from "react";
import "@fortawesome/fontawesome-free/css/all.min.css";
import type { IconifyJSON } from "@iconify/types";

type MermaidApi = Awaited<typeof import("mermaid")>["default"];

let mermaidLoader: Promise<MermaidApi> | null = null;
let mermaidConfigured = false;

// ── Icon lookup map: prefix → { iconName → svgBody } ──
const ICON_PACKS: Record<string, IconifyJSON> = {};

// ── Official brand colors for known icons ──
const BRAND_COLORS: Record<string, string> = {
  // Brands (fab:)
  docker: "#2496ED",
  php: "#777BB4",
  python: "#3776AB",
  java: "#ED8B00",
  "js-square": "#F7DF1E",
  "node-js": "#339933",
  react: "#61DAFB",
  angular: "#DD0031",
  vuejs: "#4FC08D",
  android: "#3DDC84",
  apple: "#A2AAAD",
  windows: "#0078D6",
  linux: "#FCC624",
  github: "#E6EDF3",
  aws: "#FF9900",
  google: "#4285F4",
  microsoft: "#00A4EF",
  npm: "#CB3837",
  rust: "#CE422B",
  golang: "#00ADD8",
  wordpress: "#21759B",
  laravel: "#FF2D20",
  symfony: "#E6E6E6",
  // Solid icons (fa:) — semantic colors
  shield: "#22d3ee",           // cyan — security
  "shield-halved": "#22d3ee",
  lock: "#facc15",             // yellow — auth/crypto
  "lock-open": "#ef4444",      // red — unlocked
  key: "#fbbf24",              // amber
  bug: "#ef4444",              // red — vulnerability
  "triangle-exclamation": "#f97316", // orange — warning
  "circle-exclamation": "#f97316",
  "circle-check": "#22c55e",   // green — ok
  check: "#22c55e",
  user: "#60a5fa",             // blue — person
  "user-secret": "#a78bfa",    // purple — attacker
  users: "#60a5fa",
  server: "#94a3b8",           // slate — infrastructure
  database: "#60a5fa",         // blue — storage
  cloud: "#38bdf8",            // sky — cloud/infra
  globe: "#34d399",            // emerald — web
  code: "#a78bfa",             // violet — code
  "code-branch": "#a78bfa",
  file: "#94a3b8",             // slate
  "file-code": "#a78bfa",
  folder: "#fbbf24",           // amber — directory
  "folder-open": "#fbbf24",
  terminal: "#22c55e",         // green — CLI
  gear: "#94a3b8",             // slate — settings
  gears: "#94a3b8",
  "network-wired": "#60a5fa",
  upload: "#38bdf8",
  download: "#38bdf8",
  fire: "#ef4444",             // red — danger
  bolt: "#facc15",             // yellow — power
  eye: "#60a5fa",
  "eye-slash": "#ef4444",
  // MDI icons
  security: "#22d3ee",
  api: "#a78bfa",
  webhook: "#34d399",
  lan: "#60a5fa",
  web: "#34d399",
  "code-braces": "#a78bfa",
  incognito: "#a78bfa",
};

// Default color for unrecognized icons
const DEFAULT_ICON_COLOR = "#38bdf8";

async function getMermaid(): Promise<MermaidApi> {
  if (!mermaidLoader) {
    mermaidLoader = Promise.all([
      import("mermaid"),
      import("@iconify-json/fa6-solid"),
      import("@iconify-json/fa6-brands"),
      import("@iconify-json/mdi"),
    ]).then(([mermaidModule, fa6SolidModule, fa6BrandsModule, mdiModule]) => {
      const mermaid = mermaidModule.default;
      const fa6SolidIcons = fa6SolidModule.icons;
      const fa6BrandsIcons = fa6BrandsModule.icons;
      const mdiIcons = mdiModule.icons;

      ICON_PACKS.fa = fa6SolidIcons;
      ICON_PACKS.fas = fa6SolidIcons;
      ICON_PACKS["fa6-solid"] = fa6SolidIcons;
      ICON_PACKS.fab = fa6BrandsIcons;
      ICON_PACKS["fa6-brands"] = fa6BrandsIcons;
      ICON_PACKS.mdi = mdiIcons;

      if (!mermaidConfigured) {
        mermaid.registerIconPacks([
          { name: "fa", icons: fa6SolidIcons },
          { name: "fas", icons: fa6SolidIcons },
          { name: "fab", icons: fa6BrandsIcons },
          { name: "fa6-solid", icons: fa6SolidIcons },
          { name: "fa6-brands", icons: fa6BrandsIcons },
          { name: "mdi", icons: mdiIcons },
        ]);

        mermaid.initialize({
          startOnLoad: false,
          theme: "dark",
          securityLevel: "strict",
          htmlLabels: true,
          fontFamily: "'JetBrains Mono', ui-monospace, monospace",
          flowchart: {
            useMaxWidth: true,
            curve: "basis",
            nodeSpacing: 50,
            rankSpacing: 50,
          },
          themeVariables: {
            darkMode: true,
            primaryColor: "#1e3a5f",
            primaryTextColor: "#e2e8f0",
            primaryBorderColor: "#38bdf8",
            lineColor: "#64748b",
            secondaryColor: "#1e293b",
            secondaryTextColor: "#e2e8f0",
            secondaryBorderColor: "#6366f1",
            tertiaryColor: "#1a1a2e",
            tertiaryTextColor: "#e2e8f0",
            tertiaryBorderColor: "#818cf8",
            background: "#0c0c14",
            mainBkg: "#1e293b",
            nodeBorder: "#38bdf8",
            nodeTextColor: "#e2e8f0",
            clusterBkg: "#0f172a",
            clusterBorder: "#475569",
            titleColor: "#f1f5f9",
            edgeLabelBackground: "#0f172a",
            labelTextColor: "#e2e8f0",
            textColor: "#e2e8f0",
            noteBkgColor: "#1e293b",
            noteTextColor: "#e2e8f0",
            noteBorderColor: "#475569",
            fontSize: "13px",
          },
        });
        mermaidConfigured = true;
      }

      return mermaid;
    });
  }

  return mermaidLoader;
}

/**
 * Look up an icon's SVG body from the loaded icon packs.
 * Returns an inline SVG string with brand-appropriate coloring, or null.
 */
function getIconSvg(prefix: string, iconName: string, sizePx = 24): string | null {
  const pack = ICON_PACKS[prefix];
  if (!pack) return null;
  const icon = pack.icons[iconName];
  if (!icon) return null;
  const w = pack.width || 512;
  const h = pack.height || 512;
  const color = BRAND_COLORS[iconName] || DEFAULT_ICON_COLOR;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${sizePx}" height="${sizePx}" fill="${color}" style="display:inline-block;vertical-align:middle;margin-right:6px;flex-shrink:0;filter:drop-shadow(0 0 2px ${color}40)">${icon.body}</svg>`;
}

function humanizeIconName(iconName: string): string {
  return iconName.replace(/-/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());
}

// Match patterns like "fa:user", "fab:php", "mdi:database" in text
const ICON_RE = /\b(fa[bs]?|fa6-solid|fa6-brands|mdi):([a-z0-9][a-z0-9-]*)/gi;

/**
 * Post-process rendered SVG: replace literal "prefix:icon-name" text
 * with actual inline SVG icons. Works on both <text> elements (SVG labels)
 * and <span>/<div> elements (htmlLabels inside foreignObject).
 */
function injectIcons(svgHtml: string): string {
  const parser = new DOMParser();
  const doc = parser.parseFromString(svgHtml, "image/svg+xml");
  const svg = doc.querySelector("svg");
  if (!svg) return svgHtml;
  let replacedHtmlLabel = false;

  // Process foreignObject HTML labels (most common with htmlLabels: true)
  svg.querySelectorAll("foreignObject span, foreignObject div, foreignObject p").forEach((el) => {
    const html = el.innerHTML;
    if (!ICON_RE.test(html)) return;
    ICON_RE.lastIndex = 0;
    const updated = html.replace(ICON_RE, (match, prefix, name) => {
      const iconSvg = getIconSvg(prefix.toLowerCase(), name, 24);
      return iconSvg || match; // Keep original text if icon not found
    });
    if (updated !== html) {
      replacedHtmlLabel = true;
      el.innerHTML = updated;
    }
  });

  // If Mermaid falls back to plain SVG text labels, keep them readable instead
  // of surfacing raw `fa:*` / `mdi:*` tokens to the user.
  if (!replacedHtmlLabel) {
    svg.querySelectorAll("text, tspan").forEach((textEl) => {
      const content = textEl.textContent || "";
      ICON_RE.lastIndex = 0;
      if (!ICON_RE.test(content)) return;
      ICON_RE.lastIndex = 0;
      textEl.textContent = content.replace(ICON_RE, (_match, _prefix, name) => humanizeIconName(name));
    });
  }

  return new XMLSerializer().serializeToString(svg);
}

let _mermaidIdCounter = 0;

export interface MermaidDiagramProps {
  spec: string;
  id: string;
  fallbackImage?: string;
}

export function MermaidDiagram({ spec, id, fallbackImage }: MermaidDiagramProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [svg, setSvg] = useState<string>("");
  const [error, setError] = useState(false);

  useEffect(() => {
    if (!spec) {
      setError(true);
      return;
    }

    let cleanSpec = spec.trim();
    cleanSpec = cleanSpec
      .replace(/^```(?:mermaid)?\s*\n?/i, "")
      .replace(/\n?```\s*$/i, "")
      .trim();

    let cancelled = false;
    (async () => {
      try {
        const mermaid = await getMermaid();
        const { svg: rendered } = await mermaid.render(
          `mermaid-${id}-${++_mermaidIdCounter}`,
          cleanSpec,
        );
        if (!cancelled) {
          // Post-process: inject real SVG icons where "fa:icon" text appears
          const withIcons = injectIcons(rendered);
          setSvg(withIcons);
          setError(false);
        }
      } catch (err) {
        console.error("Mermaid render error:", err);
        if (!cancelled) setError(true);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [spec, id]);

  if (error && fallbackImage) {
    return (
      <img
        src={fallbackImage}
        alt="Architecture diagram"
        className="max-w-full"
        draggable={false}
      />
    );
  }

  if (error) {
    return (
      <div className="w-full max-w-4xl mx-auto">
        <div className="rounded-lg border border-[#1a1a2e] overflow-hidden">
          <div className="flex items-center justify-between bg-[#12121f] px-4 py-2 border-b border-[#1a1a2e]">
            <span className="text-[10px] text-text-muted uppercase tracking-wider font-medium">
              Mermaid Source
            </span>
            <button
              onClick={() => navigator.clipboard.writeText(spec)}
              className="text-[10px] px-2 py-1 rounded bg-accent-primary/10 text-accent-primary hover:bg-accent-primary/20"
            >
              Copy
            </button>
          </div>
          <pre className="p-4 text-xs font-mono text-text-secondary leading-relaxed overflow-x-auto whitespace-pre-wrap">
            {spec || "No diagram specification available."}
          </pre>
        </div>
      </div>
    );
  }

  if (!svg) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="w-full flex items-center justify-center [&_svg]:max-w-full"
      dangerouslySetInnerHTML={{ __html: svg }}
    />
  );
}

export default MermaidDiagram;
