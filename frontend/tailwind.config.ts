/**
 * ShadowHawk Platform Tailwind Configuration
 */
import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}", "./app/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        slate: {
          950: "#0b0f1a"
        },
        brand: {
          500: "#5b8cff",
          600: "#3e6bff"
        }
      }
    }
  },
  plugins: []
};

export default config;
