/**
 * ShadowHawk Platform Client Layout Wrapper
 */
"use client";

import type { ReactNode } from "react";
import { usePathname } from "next/navigation";
import { AppShell } from "@/components/layouts/AppShell";

const authRoutes = new Set(["/login", "/logout"]);

export const ClientLayout = ({ children }: { children: ReactNode }) => {
  const pathname = usePathname();
  if (authRoutes.has(pathname)) {
    return <>{children}</>;
  }

  return <AppShell>{children}</AppShell>;
};
