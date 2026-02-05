/**
 * ShadowHawk Platform Sidebar Navigation
 */
"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const navItems = [
  { href: "/dashboard", label: "Executive Dashboard" },
  { href: "/threats", label: "SOC Analyst" },
  { href: "/threats?view=modeling", label: "Threat Modeling" },
  { href: "/mitre", label: "MITRE ATT&CK" },
  { href: "/correlation", label: "Correlation" },
  { href: "/risks", label: "Risk Management" },
  { href: "/reports", label: "Reports" }
];

export const Sidebar = () => {
  const pathname = usePathname();

  return (
    <nav className="flex h-full flex-col gap-4 p-6" aria-label="Primary">
      <div>
        <p className="text-xs uppercase tracking-[0.3em] text-slate-500">ShadowHawk</p>
        <h1 className="text-lg font-semibold text-white">Platform</h1>
      </div>
      <div className="space-y-2">
        {navItems.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "block rounded-lg px-3 py-2 text-sm font-medium transition hover:bg-slate-800",
                isActive ? "bg-slate-800 text-white" : "text-slate-300"
              )}
            >
              {item.label}
            </Link>
          );
        })}
      </div>
      <div className="mt-auto text-xs text-slate-500">
        <p>v1.0 Enterprise</p>
        <p>Realtime posture &amp; response</p>
      </div>
    </nav>
  );
};
