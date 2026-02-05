/**
 * ShadowHawk Platform Logout Page
 */
"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Card } from "@/components/ui/Card";
import { useAuth } from "@/hooks/useAuth";

const LogoutPage = () => {
  const router = useRouter();
  const { logout } = useAuth();

  useEffect(() => {
    const runLogout = async () => {
      await logout();
      router.replace("/login");
    };

    runLogout();
  }, [logout, router]);

  return (
    <Card className="w-full max-w-md text-center">
      <p className="text-sm text-slate-400">Signing you out...</p>
      <h1 className="mt-2 text-2xl font-semibold text-white">See you soon</h1>
    </Card>
  );
};

export default LogoutPage;
