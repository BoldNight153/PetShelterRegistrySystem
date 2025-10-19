import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { useServices } from '@/services/hooks'
import { refresh as apiRefresh } from './api'

type User = { id?: string; email?: string; name?: string; emailVerified?: string | null; roles?: string[]; permissions?: string[] } | null;

type AuthContextValue = {
  user: User;
  authenticated: boolean;
  initializing: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => Promise<void>;
  setUser: (u: User) => void;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User>(null);
  const [initializing, setInitializing] = useState<boolean>(true);
  const services = useServices()

  const authenticated = !!user;

  const login = useCallback(async (email: string, password: string) => {
    const data = await services.auth.login({ email, password });
    // Set immediately so UI can reflect basic identity
    setUser(data);
    // Hydrate roles/permissions and any server-side fields
    try {
      const res = await fetch('/auth/me', { credentials: 'include' });
      if (res.ok) {
        const me = await res.json();
        setUser(me);
      }
  } catch { /* ignore */ }
  }, [services]);

  const register = useCallback(async (email: string, password: string, name: string) => {
    const data = await services.auth.register({ email, password, name });
    setUser(data);
    try {
      const res = await fetch('/auth/me', { credentials: 'include' });
      if (res.ok) {
        const me = await res.json();
        setUser(me);
      }
  } catch { /* ignore */ }
  }, [services]);

  const logout = useCallback(async () => {
    try { await services.auth.logout(); } finally { setUser(null); }
  }, [services]);

  // Auto-refresh access token periodically; also attempt on mount
  useEffect(() => {
    const attempt = async () => {
      try {
        const res = await services.auth.refresh();
        if (res && authenticated) {
          // refresh success – keep user; server sets cookies
        }
      } catch {
        // ignore
      }
    };
    attempt();
    const timer = window.setInterval(attempt, 12 * 60 * 1000); // every 12 minutes
    return () => { window.clearInterval(timer); };
  }, [authenticated, services]);

  const value = useMemo(() => ({ user, authenticated, login, register, logout, setUser, initializing }), [user, authenticated, login, register, logout, initializing]);
  // Hydrate from /auth/me on mount
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch('/auth/me', { credentials: 'include' });
        if (res.ok) {
          const data = await res.json();
          if (data?.email) setUser(data);
        }
      } catch {
        // ignore
      }
      finally {
        setInitializing(false);
      }
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
export async function withAutoRefresh(fn: () => Promise<Response>, refreshFn?: () => Promise<unknown>): Promise<Response> {
  let res = await fn();
  if (res.status === 401) {
    if (refreshFn) await refreshFn(); else await apiRefresh();
    res = await fn();
  }
  return res;
}

// Route guard component
import { Navigate, useLocation } from "react-router-dom";
import type { ReactElement } from "react";
export function ProtectedRoute({ children }: { children: ReactElement }) {
  const { authenticated, initializing } = useAuth();
  const location = useLocation();
  if (initializing) return null;
  if (!authenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  return children;
}
