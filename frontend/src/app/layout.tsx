/**
 * ShadowHawk Platform Root Layout
 */
import type { ReactNode } from "react";
import "./globals.css";
import { AuthProvider } from "@/stores/authStore";
import { ClientLayout } from "@/components/layouts/ClientLayout";

export const metadata = {
  title: "ShadowHawk Platform",
  description: "Enterprise cybersecurity command center"
};

const RootLayout = ({ children }: { children: ReactNode }) => (
  <html lang="en">
    <body>
      <AuthProvider>
        <ClientLayout>{children}</ClientLayout>
      </AuthProvider>
    </body>
  </html>
);

export default RootLayout;
