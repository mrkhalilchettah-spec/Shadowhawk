/**
 * ShadowHawk Platform Button Component
 */
"use client";

import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

type ButtonVariant = "primary" | "secondary" | "ghost";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  icon?: ReactNode;
};

const variantStyles: Record<ButtonVariant, string> = {
  primary: "bg-brand-600 text-white hover:bg-brand-500",
  secondary: "bg-slate-800 text-slate-100 hover:bg-slate-700",
  ghost: "bg-transparent text-slate-200 hover:bg-slate-900"
};

export const Button = ({
  variant = "primary",
  className,
  icon,
  children,
  ...props
}: ButtonProps) => (
  <button
    className={cn(
      "inline-flex items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-semibold transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-500 disabled:cursor-not-allowed disabled:opacity-60",
      variantStyles[variant],
      className
    )}
    {...props}
  >
    {icon}
    {children}
  </button>
);
