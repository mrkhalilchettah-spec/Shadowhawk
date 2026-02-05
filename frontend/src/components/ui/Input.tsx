/**
 * ShadowHawk Platform Input Component
 */
import type { InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export const Input = ({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) => (
  <input
    className={cn(
      "w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-500/30",
      className
    )}
    {...props}
  />
);
