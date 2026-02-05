/**
 * ShadowHawk Platform Badge Component
 */
import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

type BadgeTone = "success" | "warning" | "critical" | "info";

const toneStyles: Record<BadgeTone, string> = {
  success: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  warning: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  critical: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  info: "bg-sky-500/15 text-sky-300 border-sky-500/30"
};

export const Badge = ({
  className,
  children,
  tone = "info",
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: BadgeTone }) => (
  <span
    className={cn(
      "inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide",
      toneStyles[tone],
      className
    )}
    {...props}
  >
    {children}
  </span>
);
