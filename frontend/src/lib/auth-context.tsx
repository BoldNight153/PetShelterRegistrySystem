import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { login as apiLogin, logout as apiLogout, refresh as apiRefresh, register as apiRegister } from "./api";

type User = { id?: string; email?: string; name?: string; emailVerified?: string | null } | null;

type AuthContextValue = {
  user: User;
  authenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => Promise<void>;
  setUser: (u: User) => void;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User>(null);

  const authenticated = !!user;

  const login = useCallback(async (email: string, password: string) => {
    const data = await apiLogin({ email, password });
    setUser(data);
  }, []);

  const register = useCallback(async (email: string, password: string, name: string) => {
    const data = await apiRegister({ email, password, name });
    setUser(data);
  }, []);

  const logout = useCallback(async () => {
    try { await apiLogout(); } finally { setUser(null); }
  }, []);

  // Auto-refresh access token periodically; also attempt on mount
  useEffect(() => {
    let timer: number | undefined;
    const attempt = async () => {
      try {
        const res = await apiRefresh();
        if (res && authenticated) {
          // refresh success – keep user; server sets cookies
        }
      } catch (_) {
        // ignore
      }
    };
    attempt();
    timer = window.setInterval(attempt, 12 * 60 * 1000); // every 12 minutes
    return () => { if (timer) window.clearInterval(timer); };
  }, [authenticated]);

  const value = useMemo(() => ({ user, authenticated, login, register, logout, setUser }), [user, authenticated, login, register, logout]);
  // Hydrate from /auth/me on mount
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/auth/me', { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          if (data?.email) setUser(data);
        }
      } catch (_) {}
    })();
  }, []);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

// Helper: wrap an API call to auto-refresh on 401 once
export async function withAutoRefresh(fn: () => Promise<Response>): Promise<Response> {
  let res = await fn();
  if (res.status === 401) {
    await apiRefresh();
    res = await fn();
  }
  return res;
}

// Route guard component
import { Navigate, useLocation } from "react-router-dom";
import type { ReactElement } from "react";
export function ProtectedRoute({ children }: { children: ReactElement }) {
  const { authenticated } = useAuth();
  const location = useLocation();
  if (!authenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return children;
}
