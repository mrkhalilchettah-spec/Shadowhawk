/**
 * ShadowHawk Platform Authentication Layout
 */
import type { ReactNode } from "react";

const AuthLayout = ({ children }: { children: ReactNode }) => (
  <div className="flex min-h-screen items-center justify-center bg-slate-950 px-6">
    {children}
  </div>
);

export default AuthLayout;
