import React, { createContext, useCallback, useContext, useEffect, useMemo } from "react";
import { useAppDispatch, useAppSelector } from '@/store/hooks'
import { login as loginThunk, register as registerThunk, logout as logoutThunk, refresh as refreshThunk, setUser as setUserAction, setInitializing as setInitializingAction, selectAuthUser, selectAuthInitializing } from '@/store/slices/authSlice'
import type { UserDetail } from '@/services/interfaces/types'
import { ReactReduxContext, Provider as ReduxProvider } from 'react-redux'
import { useServices } from '@/services/hooks'
import { createStoreWithServices } from '@/store/store'
import { refresh as apiRefresh } from '@/lib/api'

type User = UserDetail | null;

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
  // Ensure we have access to Services so that created local stores are DI-enabled in tests
  const services = useServices()
  const reduxCtx = useContext(ReactReduxContext as any)
  const needsLocalStore = !reduxCtx || !(reduxCtx as any).store
  const localStore = useMemo(() => createStoreWithServices(services), [services])

  if (needsLocalStore) {
    return (
      <ReduxProvider store={localStore}>
        <AuthInner>{children}</AuthInner>
      </ReduxProvider>
    )
  }

  return <AuthInner>{children}</AuthInner>
}

function AuthInner({ children }: { children: React.ReactNode }) {
  const dispatch = useAppDispatch()
  const user = useAppSelector(selectAuthUser)
  const initializing = useAppSelector(selectAuthInitializing)

  const authenticated = !!user;

  const login = useCallback(async (email: string, password: string) => {
    const action = await dispatch(loginThunk({ email, password }))
    return action.payload
  }, [dispatch])

  const register = useCallback(async (email: string, password: string, name: string) => {
    const action = await dispatch(registerThunk({ email, password, name }))
    return action.payload
  }, [dispatch])

  const logout = useCallback(async () => {
    await dispatch(logoutThunk())
  }, [dispatch])

  // Periodically refresh token only while authenticated
  useEffect(() => {
    if (!authenticated) return
    const timer = window.setInterval(() => {
      void dispatch(refreshThunk())
    }, 12 * 60 * 1000)
    return () => { window.clearInterval(timer) }
  }, [authenticated, dispatch])

  const setUser = useCallback((u: User) => { dispatch(setUserAction(u)) }, [dispatch])

  const value = useMemo(() => ({ user, authenticated, login, register, logout, setUser, initializing }), [user, authenticated, login, register, logout, initializing, setUser]);

  // Hydrate from /auth/me on mount via refresh thunk and clear initializing flag
  useEffect(() => {
    let cancelled = false
    void (async () => {
      try {
        await dispatch(refreshThunk())
      } catch {
        // ignore
      } finally {
        if (!cancelled) dispatch(setInitializingAction(false))
      }
    })()
    // Dev helper: fetch /auth/mode and log backend-visible cookie/state to aid debugging
    if (import.meta.env.DEV) {
      void (async () => {
        try {
          const r = await fetch('/auth/mode', { credentials: 'include' })
          try {
            const j = await r.json()
            console.info('DEBUG /auth/mode ->', r.status, j)
          } catch {
            console.info('DEBUG /auth/mode -> non-json', r.status)
          }
        } catch (err) {
          console.warn('DEBUG /auth/mode fetch failed', err)
        }
      })()
    }
    return () => { cancelled = true }
  }, [dispatch])

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
