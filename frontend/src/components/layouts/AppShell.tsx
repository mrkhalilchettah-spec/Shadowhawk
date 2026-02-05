/**
 * ShadowHawk Platform Application Shell
 */
"use client";

import type { ReactNode } from "react";
import { Sidebar } from "@/components/layouts/Sidebar";
import { TopBar } from "@/components/layouts/TopBar";

export const AppShell = ({ children }: { children: ReactNode }) => (
  <div className="min-h-screen bg-slate-950 text-slate-100">
    <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[280px_1fr]">
      <aside className="border-b border-slate-800 bg-slate-950 lg:border-b-0 lg:border-r">
        <Sidebar />
      </aside>
      <div className="flex flex-col">
        <TopBar />
        <main className="flex-1 px-6 py-8 lg:px-10" aria-live="polite">
          {children}
        </main>
      </div>
    </div>
  </div>
);
