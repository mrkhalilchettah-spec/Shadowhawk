/**
 * ShadowHawk Platform Top Bar
 */
"use client";

import Link from "next/link";
import { Button } from "@/components/ui/Button";
import { useAuth } from "@/hooks/useAuth";

export const TopBar = () => {
  const { user } = useAuth();

  return (
    <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-8 py-6">
      <div>
        <p className="text-sm text-slate-400">Welcome back</p>
        <h2 className="text-xl font-semibold text-white">{user?.name ?? "Security Leader"}</h2>
      </div>
      <div className="flex items-center gap-3">
        <div className="text-right">
          <p className="text-sm font-semibold text-white">{user?.role ?? "Executive"}</p>
          <p className="text-xs text-slate-400">{user?.organization ?? "ShadowHawk"}</p>
        </div>
        <Link href="/logout">
          <Button variant="secondary">Logout</Button>
        </Link>
      </div>
    </header>
  );
};
