/* eslint-disable react-refresh/only-export-components -- context + provider must coexist in one file */
import { createContext, useState, useEffect, useCallback, ReactNode } from "react";
import { AuthUser } from "../types";

export interface AuthContextValue {
  user: AuthUser | null;
  isAdmin: boolean;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    void (async () => {
      try {
        const res = await fetch("/api/auth/me", { credentials: "include" });
        if (res.ok) {
          const data = await res.json() as { user: AuthUser };
          setUser(data.user);
        }
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const login = useCallback(async (username: string, password: string): Promise<void> => {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: "Login failed" })) as { error?: string };
      throw new Error(body.error ?? "Login failed");
    }
    const data = await res.json() as { user: AuthUser };
    setUser(data.user);
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, isAdmin: user?.role === "admin", loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}
