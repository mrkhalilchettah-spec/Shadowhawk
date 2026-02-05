/**
 * ShadowHawk Platform Auth Utilities
 */
import type { UserProfile } from "@/types";

const STORAGE_KEY = "shadowhawk:user";

const defaultUser: UserProfile = {
  id: "user-1",
  name: "Avery Coleman",
  role: "Executive",
  organization: "ShadowHawk Global"
};

export const getStoredUser = (): UserProfile | null => {
  if (typeof window === "undefined") {
    return null;
  }

  const stored = window.localStorage.getItem(STORAGE_KEY);
  return stored ? (JSON.parse(stored) as UserProfile) : defaultUser;
};

export const loginUser = async (email: string, password: string): Promise<UserProfile> => {
  if (!email || !password) {
    throw new Error("Email and password are required");
  }

  const user = { ...defaultUser, name: email.split("@")[0] ?? defaultUser.name };

  if (typeof window !== "undefined") {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
  }

  return user;
};

export const logoutUser = async (): Promise<void> => {
  if (typeof window !== "undefined") {
    window.localStorage.removeItem(STORAGE_KEY);
  }
};
