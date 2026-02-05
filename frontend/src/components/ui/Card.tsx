/**
 * ShadowHawk Platform Card Component
 */
import type { HTMLAttributes, PropsWithChildren } from "react";
import { cn } from "@/lib/utils";

export const Card = ({
  className,
  children,
  ...props
}: PropsWithChildren<HTMLAttributes<HTMLDivElement>>) => (
  <div
    className={cn(
      "rounded-xl border border-slate-800 bg-slate-900/60 p-6 shadow-lg shadow-black/20",
      className
    )}
    {...props}
  >
    {children}
  </div>
);
