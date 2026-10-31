import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#09090b", // zinc-950
          panel: "#121215",
          border: "#27272a", // zinc-800
          critical: "#ef4444", // red-500
          high: "#f59e0b", // amber-500
          medium: "#eab308", // yellow-500
          low: "#3b82f6", // blue-500
        },
      },
      fontFamily: {
        mono: [
          "var(--font-geist-mono)",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Monaco",
          "Consolas",
          "monospace",
        ],
      },
      borderRadius: {
        none: "0px",
        DEFAULT: "0px",
        sm: "0px",
        md: "0px",
        lg: "0px",
      },
    },
  },
  plugins: [],
};

export default config;

