import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        bg: {
          primary: "#0a0a1a",
          secondary: "#111128",
          tertiary: "#16163a",
          card: "#1a1a3e",
          hover: "#222255",
        },
        accent: {
          primary: "#00d4ff",
          secondary: "#64ffda",
          purple: "#bb86fc",
          orange: "#ff8c00",
          warning: "#ffbb33",
          danger: "#ff4444",
          success: "#00C851",
        },
        text: {
          primary: "#e0e0e0",
          secondary: "#a0a0b0",
          muted: "#6b6b80",
        },
        border: {
          DEFAULT: "#2a2a4a",
          light: "#3a3a5a",
        },
      },
      fontFamily: {
        sans: ['"Inter"', '"Segoe UI"', "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Consolas"', "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
