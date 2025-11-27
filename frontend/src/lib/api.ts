import type {
  AccountSecuritySnapshot,
  SecurityAlertSettings,
  SecurityMfaEnrollmentPrompt,
  SecurityMfaEnrollmentResult,
  SecurityRecoverySettings,
  SecuritySession,
  SecurityAuthenticatorCatalogEntry,
} from '@/types/security-settings'
import { normalizeAccountSecuritySnapshot, normalizeSecurityAuthenticatorCatalogEntry } from '@/types/security-settings'
import type {
  NotificationSettings,
  NotificationSettingsInput,
  NotificationDevice,
  NotificationDeviceRegistrationInput,
} from '@/types/notifications'
import { normalizeNotificationSettings } from '@/types/notifications'
import type { LoginDeviceMetadata, LoginChallengeResponse, VerifyMfaChallengeInput } from '@/types/auth'
import { isLoginChallengeResponse } from '@/types/auth'
import type {
  AdminAuthenticatorCatalogRecord,
  CreateAdminAuthenticatorInput,
  UpdateAdminAuthenticatorInput,
} from '@/services/interfaces/admin.interface'

// Minimal API client for auth with CSRF double-submit and cookie-based session
type LoginInput = { email: string; password: string } & LoginDeviceMetadata;
type RegisterInput = { email: string; password: string; name?: string };
type MfaVerifyInput = VerifyMfaChallengeInput;

type ApiError = Error & { payload?: unknown; status?: number };

const API_BASE = "/"; // Vite proxy should send /auth to backend

function resolveErrorMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object') {
    const record = body as Record<string, unknown>;
    if (typeof record.error === 'string' && record.error.trim()) {
      return record.error.trim();
    }
    if (record.error && typeof record.error === 'object') {
      const nested = record.error as Record<string, unknown>;
      if (typeof nested.message === 'string' && nested.message.trim()) {
        return nested.message.trim();
      }
    }
    if (typeof record.message === 'string' && record.message.trim()) {
      return record.message.trim();
    }
  }
  return fallback;
}

function buildApiError(res: Response, body: unknown, fallback: string): ApiError {
  const message = resolveErrorMessage(body, fallback || `Request failed (${res.status})`);
  const error = new Error(message) as ApiError;
  error.payload = body;
  error.status = res.status;
  return error;
}

async function getCsrfToken(): Promise<string> {
  const res = await fetch(`${API_BASE}auth/csrf`, {
    method: "GET",
    credentials: "include",
  });
  if (!res.ok) throw new Error("Failed to fetch CSRF token");
  const data = await res.json();
  // Backend returns { csrfToken } and also sets a 'csrfToken' cookie; header must equal cookie value
  return (data.csrfToken as string) ?? (data.token as string);
}

export async function login(input: LoginInput) {
  const csrf = await getCsrfToken();
  const res = await fetch(`${API_BASE}auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
    },
    credentials: "include",
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw buildApiError(res, err, `Login failed (${res.status})`);
  }
  const body = await res.json().catch(() => ({}));

  const challengePayload: LoginChallengeResponse | null = (() => {
    if (isLoginChallengeResponse(body)) return body;
    if (body && typeof body === 'object' && 'challengeRequired' in body && (body as any).challengeRequired === true) {
      return body as LoginChallengeResponse;
    }
    if (body && typeof body === 'object' && 'challenge' in body) {
      return { challengeRequired: true, challenge: (body as any).challenge } as LoginChallengeResponse;
    }
    return null;
  })();

  if (res.status === 202 || challengePayload) {
    if (!challengePayload?.challenge) throw new Error('Missing MFA challenge payload');
    return challengePayload;
  }

  // Option A: post-login CSRF sync — ensure browser has processed Set-Cookie and
  // the server sees the session cookies before callers continue. This reduces
  // races where a subsequent reload or automatic refresh happens before the
  // refreshToken/accessToken cookies are present server-side.
  // We do a small retry loop against GET /auth/csrf which is cheap and returns
  // the server-side CSRF value (and also sets the cookie). If it succeeds we
  // assume the session cookies are active.
  try {
    const maxAttempts = 5;
    const delayMs = 200;
    for (let i = 0; i < maxAttempts; i++) {
      try {
        await getCsrfToken();
  // success — cookies are visible to server
  // Dev-only log
        if ((import.meta as any)?.env?.DEV) console.debug('[auth.login] post-login csrf sync ok (attempt)', i + 1);
        break;
      } catch (e) {
        // last attempt -> rethrow so outer catch handles logging below
        if (i === maxAttempts - 1) throw e;
        // wait a short while and retry
        await new Promise((r) => setTimeout(r, delayMs));
      }
    }
  } catch (e) {
    // Don't fail the login flow for non-fatal timing issues; log in dev so
    // we can iterate if stable failures remain.
    if ((import.meta as any)?.env?.DEV) console.warn('[auth.login] post-login csrf sync failed, proceeding anyway', e);
  }

  return body;
}

export async function verifyMfaChallenge(input: MfaVerifyInput) {
  const csrf = await getCsrfToken()
  const res = await fetch(`${API_BASE}auth/mfa/verify`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrf,
    },
    credentials: 'include',
    body: JSON.stringify(input),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw buildApiError(res, err, `Verification failed (${res.status})`)
  }
  return res.json()
}

export async function register(input: RegisterInput) {
  const csrf = await getCsrfToken();
  const res = await fetch(`${API_BASE}auth/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
    },
    credentials: "include",
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const msg = typeof err?.error === 'string' ? err.error : (err?.error?.message || null);
    throw new Error(msg || `Registration failed (${res.status})`);
  }
  return res.json();
}

export async function logout() {
  const csrf = await getCsrfToken();
  const res = await fetch(`${API_BASE}auth/logout`, {
    method: "POST",
    headers: { "X-CSRF-Token": csrf },
    credentials: "include",
  });
  if (!res.ok) throw new Error("Logout failed");
}

export async function refresh() {
  // Defensive: fetch a fresh CSRF token, then wait until the browser's
  // document.cookie contains the corresponding csrfToken cookie before
  // issuing the refresh POST. This reduces races where the client sends
  // an X-CSRF-Token header but the Cookie header isn't yet attached by
  // the browser (observed in dev with rapid back-to-back requests).
  // We still retry once if the server rejects with 403.
  for (let attempt = 0; attempt < 2; attempt++) {
    const csrf = await getCsrfToken();

    // Wait for the browser to expose the csrfToken cookie in document.cookie.
    // Use a short polling loop — if the cookie appears we proceed; otherwise
    // we still send the request after the timeout to avoid hanging forever.
    try {
      if ((import.meta as any)?.env?.DEV) console.debug('[auth.refresh] pre-flight csrf', csrf, 'attempt', attempt + 1);
    } catch {}

    const maxWaitMs = 500; // total time to wait for cookie to appear
    const pollIntervalMs = 50;
    const start = Date.now();
    while (Date.now() - start < maxWaitMs) {
      try {
        // If running in a browser, check document.cookie. In non-browser
        // environments this will throw; ignore there.
        if (typeof document !== 'undefined' && document.cookie && document.cookie.indexOf('csrfToken=') !== -1) {
          // Quick heuristic: check that some fragment of the token appears in the cookie
          if (document.cookie.indexOf(csrf.split('.')[0]) !== -1 || document.cookie.indexOf(csrf.split('.').pop() || '') !== -1) {
            // cookie observed and appears to contain our token
            if ((import.meta as any)?.env?.DEV) console.debug('[auth.refresh] cookie visible before request');
            break;
          }
        }
      } catch {
        // Non-browser environment; skip waiting
        break;
      }
      await new Promise((r) => setTimeout(r, pollIntervalMs));
    }

    // Dev-only debug: log the csrf token used for the refresh so it can be
    // correlated with server logs and recorder traces.
    try {
      if ((import.meta as any)?.env?.DEV) console.debug('[auth.refresh] attempt', attempt + 1, 'csrf', csrf);
    } catch {}

    const res = await fetch(`${API_BASE}auth/refresh`, {
      method: 'POST',
      headers: { 'X-CSRF-Token': csrf },
      credentials: 'include',
    });
    if (res.ok) return res.json();
    // If first attempt failed due to CSRF, try once more after re-fetching token
    if (res.status === 403 && attempt === 0) {
      continue;
    }
    return null;
  }
  return null;
}

export async function me() {
  const res = await fetch(`${API_BASE}auth/me`, { credentials: 'include' });
  if (!res.ok) return null;
  return res.json();
}

export type UpdateProfileInput = {
  name?: string | null;
  avatarUrl?: string | null;
  title?: string | null;
  department?: string | null;
  pronouns?: string | null;
  timezone?: string | null;
  locale?: string | null;
  phone?: string | null;
  bio?: string | null;
};

export async function updateProfile(input: UpdateProfileInput) {
  const csrf = await getCsrfToken();
  const res = await fetch(`${API_BASE}auth/me`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof (err as any)?.error === 'string' ? (err as any).error : 'Failed to update profile');
  }
  return res.json();
}

// ----------------------
// Admin Settings API
// ----------------------

// Minimal JSON value type for settings
type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

type SettingsMap = Record<string, Record<string, JsonValue>>;

export async function loadSettings(category?: string): Promise<SettingsMap> {
  const url = category ? `/admin/settings?category=${encodeURIComponent(category)}` : `/admin/settings`;
  const res = await fetch(url, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load settings');
  const data = await res.json();
  return (data.settings ?? {}) as SettingsMap;
}

export async function saveSettings(category: string, entries: { key: string; value: JsonValue }[]) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/settings`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ category, entries })
  });
  if (!res.ok) throw new Error('Failed to save settings');
  return res.json();
}

// ----------------------
// Admin RBAC API
// ----------------------

type Role = { id: string; name: string; rank: number; description?: string | null };
type Permission = { id: string; name: string; description?: string | null };
type UserSummary = { id: string; email: string; name?: string | null; roles: string[] };
type UserSummaryWithLock = UserSummary & { lock: { reason: string; until: string | null } | null };

export async function listRoles(): Promise<Role[]> {
  const res = await fetch(`/admin/roles`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load roles');
  return res.json();
}

export async function upsertRole(input: { name: string; rank?: number; description?: string }) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/roles/upsert`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error('Failed to upsert role');
  return res.json();
}

export async function deleteRole(name: string) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/roles/${encodeURIComponent(name)}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) throw new Error('Failed to delete role');
}

export async function listPermissions(): Promise<Permission[]> {
  const res = await fetch(`/admin/permissions`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load permissions');
  return res.json();
}

export async function listRolePermissions(roleName: string): Promise<Permission[]> {
  const res = await fetch(`/admin/roles/${encodeURIComponent(roleName)}/permissions`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load role permissions');
  return res.json();
}

export async function grantPermission(roleName: string, permission: string) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/permissions/grant`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ roleName, permission }),
  });
  if (!res.ok) throw new Error('Failed to grant permission');
  return res.json();
}

export async function revokePermission(roleName: string, permission: string) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/permissions/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ roleName, permission }),
  });
  if (!res.ok) throw new Error('Failed to revoke permission');
  return res.json();
}

export async function searchUsers(q?: string, page = 1, pageSize = 20): Promise<{ items: UserSummaryWithLock[]; total: number; page: number; pageSize: number }> {
  const url = new URL(`/admin/users`, window.location.origin);
  if (q) url.searchParams.set('q', q);
  url.searchParams.set('page', String(page));
  url.searchParams.set('pageSize', String(pageSize));
  const res = await fetch(url.toString().replace(window.location.origin, ''), { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to search users');
  return res.json();
}

export async function getUserRoles(userId: string): Promise<string[]> {
  const res = await fetch(`/admin/users/${encodeURIComponent(userId)}/roles`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load user roles');
  const roles: Role[] = await res.json();
  return roles.map(r => r.name);
}

type UserDetail = UserSummaryWithLock & {
  createdAt?: string | null;
  lastLoginAt?: string | null;
  metadata?: Record<string, unknown> | null;
}

export async function getUser(userId: string): Promise<UserDetail> {
  const res = await fetch(`/admin/users/${encodeURIComponent(userId)}`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load user');
  return res.json();
}

export async function assignUserRole(userId: string, roleName: string) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/users/assign-role`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ userId, roleName }),
  });
  if (!res.ok) throw new Error('Failed to assign role');
  return res.json();
}

export async function revokeUserRole(userId: string, roleName: string) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/users/revoke-role`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ userId, roleName }),
  });
  if (!res.ok) throw new Error('Failed to revoke role');
  return res.json();
}

export async function lockUser(userId: string, reason: string, expiresAt?: string | null, notes?: string) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/users/lock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ userId, reason, expiresAt: expiresAt ?? null, notes }),
  });
  if (!res.ok) throw new Error('Failed to lock user');
  return res.json();
}

export async function unlockUser(userId: string, unlockReason?: string) {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/users/unlock`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ userId, unlockReason }),
  });
  if (!res.ok) throw new Error('Failed to unlock user');
  return res.json();
}

// List sessions for a user. Throws { status: 404 } if endpoint not available
export async function listUserSessions(userId: string) {
  const res = await fetch(`/admin/users/${encodeURIComponent(userId)}/sessions`, { credentials: 'include' });
  if (res.status === 404) throw { status: 404 };
  if (!res.ok) throw new Error('Failed to load user sessions');
  return res.json();
}

export type AuditTimelineQuery = {
  q?: string;
  action?: string;
  userId?: string;
  from?: string;
  to?: string;
  page?: number;
  pageSize?: number;
};

export async function fetchAuditTimeline(params: AuditTimelineQuery = {}) {
  const origin = typeof window !== 'undefined' && window.location?.origin ? window.location.origin : 'http://localhost:4000';
  const url = new URL('/admin/audit', origin);
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    url.searchParams.set(key, String(value));
  });
  const relativeUrl = url.pathname + url.search;
  const res = await fetch(relativeUrl, { credentials: 'include' });
  if (!res.ok) {
    const message = await res.text().catch(() => '') || `Failed to load audit timeline (${res.status})`;
    throw new Error(message);
  }
  return res.json();
}

// ----------------------
// Navigation menu API
// ----------------------

export type NavigationMenuItemResponse = {
  id: string;
  parentId?: string | null;
  title: string;
  url?: string | null;
  icon?: string | null;
  target?: string | null;
  external?: boolean | null;
  order?: number | null;
  meta?: JsonValue;
  isVisible?: boolean | null;
  isPublished?: boolean | null;
  locale?: string | null;
  children?: NavigationMenuItemResponse[];
};

export type NavigationMenuResponse = {
  id: string;
  name: string;
  title?: string | null;
  description?: string | null;
  locale?: string | null;
  isActive?: boolean | null;
  items: NavigationMenuItemResponse[];
};

export async function fetchMenus(locale?: string): Promise<NavigationMenuResponse[]> {
  const url = locale ? `/menus?locale=${encodeURIComponent(locale)}` : '/menus';
  const res = await fetch(url, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load menus');
  const data = await res.json();
  if (Array.isArray(data)) return data as NavigationMenuResponse[];
  if (Array.isArray((data as any)?.menus)) return (data as any).menus as NavigationMenuResponse[];
  return [];
}

export async function fetchMenuByName(name: string): Promise<NavigationMenuResponse | null> {
  const res = await fetch(`/menus/${encodeURIComponent(name)}`, { credentials: 'include' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('Failed to load menu');
  return res.json() as Promise<NavigationMenuResponse>;
}

// ----------------------
// Admin navigation API
// ----------------------

export type AdminMenuRecord = {
  id: string;
  name: string;
  title?: string | null;
  description?: string | null;
  locale?: string | null;
  isActive?: boolean | null;
  createdAt?: string | null;
  updatedAt?: string | null;
};

export type AdminMenuItemResponse = NavigationMenuItemResponse & {
  menuId: string;
  createdAt?: string | null;
  updatedAt?: string | null;
  children?: AdminMenuItemResponse[];
};

export type AdminMenuResponse = AdminMenuRecord & {
  items: AdminMenuItemResponse[];
};

export type CreateAdminMenuInput = {
  name: string;
  title?: string | null;
  description?: string | null;
  locale?: string | null;
  isActive?: boolean | null;
};

export type UpdateAdminMenuInput = Partial<{
  title: string | null;
  description: string | null;
  locale: string | null;
  isActive: boolean | null;
}>;

export type CreateAdminMenuItemInput = {
  title: string;
  url?: string | null;
  icon?: string | null;
  target?: string | null;
  external?: boolean | null;
  order?: number | null;
  meta?: JsonValue;
  parentId?: string | null;
  isVisible?: boolean | null;
  isPublished?: boolean | null;
  locale?: string | null;
};

export type UpdateAdminMenuItemInput = Partial<CreateAdminMenuItemInput>;

export type AdminMenuItemRecord = {
  id: string;
  menuId: string;
  parentId?: string | null;
  title: string;
  url?: string | null;
  icon?: string | null;
  target?: string | null;
  external?: boolean | null;
  order?: number | null;
  meta?: JsonValue;
  isVisible?: boolean | null;
  isPublished?: boolean | null;
  locale?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
};

export async function fetchAdminMenus(): Promise<AdminMenuResponse[]> {
  const res = await fetch('/admin/menus', { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load admin menus');
  const data = await res.json();
  if (Array.isArray(data)) return data as AdminMenuResponse[];
  if (Array.isArray((data as any)?.menus)) return (data as any).menus as AdminMenuResponse[];
  return [];
}

export async function fetchAdminMenuByName(name: string): Promise<AdminMenuResponse | null> {
  const res = await fetch(`/admin/menus/${encodeURIComponent(name)}`, { credentials: 'include' });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('Failed to load admin menu');
  return res.json() as Promise<AdminMenuResponse>;
}

export async function createAdminMenu(input: CreateAdminMenuInput): Promise<AdminMenuRecord> {
  const csrf = await getCsrfToken();
  const res = await fetch('/admin/menus', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to create menu');
  }
  return res.json() as Promise<AdminMenuRecord>;
}

export async function updateAdminMenu(id: string, input: UpdateAdminMenuInput): Promise<AdminMenuRecord> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/menus/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to update menu');
  }
  return res.json() as Promise<AdminMenuRecord>;
}

export async function deleteAdminMenu(id: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/menus/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to delete menu');
  }
}

export async function fetchAdminMenuItems(menuId: string): Promise<AdminMenuItemResponse[]> {
  const res = await fetch(`/admin/menus/${encodeURIComponent(menuId)}/items`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load menu items');
  return res.json() as Promise<AdminMenuItemResponse[]>;
}

export async function createAdminMenuItem(menuId: string, input: CreateAdminMenuItemInput): Promise<AdminMenuItemRecord> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/menus/${encodeURIComponent(menuId)}/items`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to create menu item');
  }
  return res.json() as Promise<AdminMenuItemRecord>;
}

export async function updateAdminMenuItem(id: string, input: UpdateAdminMenuItemInput): Promise<AdminMenuItemRecord> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/menus/items/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to update menu item');
  }
  return res.json() as Promise<AdminMenuItemRecord>;
}

export async function deleteAdminMenuItem(id: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/menus/items/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok && res.status !== 204) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to delete menu item');
  }
}

// ----------------------
// Admin authenticator catalog API
// ----------------------

function coerceStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const items = value
    .map((item) => (typeof item === 'string' ? item.trim() : ''))
    .filter((item) => item.length > 0);
  return items.length ? items : null;
}

const VALID_FACTOR_TYPES = new Set<AdminAuthenticatorCatalogRecord['factorType']>(['TOTP', 'SMS', 'PUSH', 'HARDWARE_KEY', 'BACKUP_CODES']);

function normalizeAuthenticatorCatalogRecord(value: unknown): AdminAuthenticatorCatalogRecord | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  const id = typeof record.id === 'string' ? record.id : null;
  const label = typeof record.label === 'string' ? record.label : null;
  if (!id || !label) return null;
  const rawFactor = typeof record.factorType === 'string' ? record.factorType.trim().toUpperCase() : 'TOTP';
  const factorType = VALID_FACTOR_TYPES.has(rawFactor as AdminAuthenticatorCatalogRecord['factorType'])
    ? (rawFactor as AdminAuthenticatorCatalogRecord['factorType'])
    : 'TOTP';
  const sortOrder = typeof record.sortOrder === 'number'
    ? record.sortOrder
    : (typeof record.sortOrder === 'string' && record.sortOrder.trim().length
        ? Number(record.sortOrder)
        : null);
  return {
    id,
    label,
    description: typeof record.description === 'string' ? record.description : (record.description ?? null) as string | null,
    factorType,
    issuer: typeof record.issuer === 'string' ? record.issuer : (record.issuer ?? null) as string | null,
    helper: typeof record.helper === 'string' ? record.helper : (record.helper ?? null) as string | null,
    docsUrl: typeof record.docsUrl === 'string' ? record.docsUrl : (record.docsUrl ?? null) as string | null,
    tags: coerceStringArray(record.tags),
    metadata: (record.metadata ?? null) as JsonValue | null,
    sortOrder: Number.isFinite(sortOrder) ? Number(sortOrder) : null,
    isArchived: typeof record.isArchived === 'boolean' ? record.isArchived : Boolean(record.isArchived),
    createdAt: record.createdAt ? String(record.createdAt) : null,
    updatedAt: record.updatedAt ? String(record.updatedAt) : null,
    archivedAt: record.archivedAt ? String(record.archivedAt) : null,
    archivedBy: record.archivedBy ? String(record.archivedBy) : null,
  } satisfies AdminAuthenticatorCatalogRecord;
}

export async function fetchAdminAuthenticators(includeArchived?: boolean): Promise<AdminAuthenticatorCatalogRecord[]> {
  const query = includeArchived ? '?includeArchived=true' : '';
  const res = await fetch(`/admin/authenticators${query}`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load authenticator catalog');
  const data = await res.json().catch(() => ({}));
  const list = Array.isArray((data as any)?.authenticators)
    ? (data as any).authenticators
    : Array.isArray(data)
      ? data
      : [];
  return list
    .map((entry: unknown) => normalizeAuthenticatorCatalogRecord(entry))
    .filter((entry: AdminAuthenticatorCatalogRecord | null): entry is AdminAuthenticatorCatalogRecord => Boolean(entry));
}

export async function createAdminAuthenticator(input: CreateAdminAuthenticatorInput): Promise<AdminAuthenticatorCatalogRecord> {
  const csrf = await getCsrfToken();
  const res = await fetch('/admin/authenticators', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to create authenticator');
  }
  const data = await res.json().catch(() => ({}));
  const normalized = normalizeAuthenticatorCatalogRecord((data as any)?.authenticator ?? data);
  if (!normalized) throw new Error('Invalid authenticator response');
  return normalized;
}

export async function updateAdminAuthenticator(id: string, input: UpdateAdminAuthenticatorInput): Promise<AdminAuthenticatorCatalogRecord> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/authenticators/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to update authenticator');
  }
  const data = await res.json().catch(() => ({}));
  const normalized = normalizeAuthenticatorCatalogRecord((data as any)?.authenticator ?? data);
  if (!normalized) throw new Error('Invalid authenticator response');
  return normalized;
}

export async function archiveAdminAuthenticator(id: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/authenticators/${encodeURIComponent(id)}/archive`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to archive authenticator');
  }
}

export async function restoreAdminAuthenticator(id: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/admin/authenticators/${encodeURIComponent(id)}/restore`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to restore authenticator');
  }
}

// ----------------------
// Account security API
// ----------------------

type SecuritySessionsResponse = {
  summary?: Record<string, unknown> | null;
  sessions?: unknown[];
  list?: unknown[];
};

export async function fetchAccountSecuritySnapshot(): Promise<AccountSecuritySnapshot> {
  const res = await fetch('/auth/security', { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load account security');
  const data = await res.json().catch(() => ({}));
  const raw = data && typeof data === 'object' && 'snapshot' in data ? (data as Record<string, unknown>).snapshot : data;
  return normalizeAccountSecuritySnapshot(raw as Record<string, unknown> | null | undefined);
}

export async function fetchSecurityAuthenticatorCatalog(options?: { includeArchived?: boolean; factorType?: string }): Promise<SecurityAuthenticatorCatalogEntry[]> {
  const params = new URLSearchParams();
  if (options?.includeArchived) params.set('includeArchived', 'true');
  if (options?.factorType) params.set('factorType', options.factorType);
  const query = params.toString();
  const res = await fetch(`/auth/security/authenticators${query ? `?${query}` : ''}`, { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load authenticator catalog');
  const data = await res.json().catch(() => ({}));
  const entries: unknown[] = Array.isArray((data as any)?.authenticators)
    ? (data as { authenticators: unknown[] }).authenticators
    : Array.isArray(data)
      ? (data as unknown[])
      : [];
  return entries
    .map((entry) => normalizeSecurityAuthenticatorCatalogEntry(entry))
    .filter((entry): entry is SecurityAuthenticatorCatalogEntry => Boolean(entry));
}

export async function listAccountSecuritySessions(): Promise<SecuritySession[]> {
  const res = await fetch('/auth/security/sessions', { credentials: 'include' });
  if (res.status === 404) {
    const snapshot = await fetchAccountSecuritySnapshot();
    return snapshot.sessions.list;
  }
  if (!res.ok) throw new Error('Failed to load sessions');
  const data = (await res.json().catch(() => ({}))) as SecuritySessionsResponse | unknown[];
  const sessionsRecord: Record<string, unknown> = {};
  if (Array.isArray((data as SecuritySessionsResponse)?.sessions)) {
    sessionsRecord.list = (data as SecuritySessionsResponse).sessions;
  } else if (Array.isArray((data as SecuritySessionsResponse)?.list)) {
    sessionsRecord.list = (data as SecuritySessionsResponse).list;
  } else if (Array.isArray(data)) {
    sessionsRecord.list = data;
  } else {
    sessionsRecord.list = [];
  }
  if (
    data &&
    typeof data === 'object' &&
    'summary' in data &&
    data.summary &&
    typeof data.summary === 'object'
  ) {
    sessionsRecord.summary = data.summary as Record<string, unknown>;
  }
  const normalized = normalizeAccountSecuritySnapshot({ sessions: sessionsRecord } as Record<string, unknown>);
  return normalized.sessions.list;
}

export async function revokeAccountSecuritySession(sessionId: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/sessions/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ sessionId }),
  });
  if (!res.ok) throw new Error('Failed to revoke session');
}

export async function revokeAllAccountSecuritySessions(): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/sessions/revoke-all', {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok) throw new Error('Failed to revoke sessions');
}

export async function trustAccountSecuritySession(sessionId: string, trust: boolean): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/sessions/trust', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify({ sessionId, trust }),
  });
  if (!res.ok) throw new Error('Failed to update session trust');
}

type ChangeAccountPasswordInput = {
  currentPassword: string;
  newPassword: string;
  signOutOthers?: boolean;
};

type TotpEnrollmentPayload = {
  label?: string;
  issuer?: string;
  accountName?: string;
  catalogId?: string;
};

export async function changeAccountPassword(input: ChangeAccountPasswordInput): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to change password');
  }
}

export async function startTotpEnrollment(input?: TotpEnrollmentPayload): Promise<SecurityMfaEnrollmentPrompt> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/mfa/totp/enroll', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input ?? {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to start enrollment');
  }
  return res.json() as Promise<SecurityMfaEnrollmentPrompt>;
}

export async function confirmTotpEnrollment(input: { ticket: string; code: string }): Promise<SecurityMfaEnrollmentResult> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/mfa/totp/confirm', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to confirm MFA enrollment');
  }
  return res.json() as Promise<SecurityMfaEnrollmentResult>;
}

export async function regenerateTotpFactor(factorId: string, input?: TotpEnrollmentPayload): Promise<SecurityMfaEnrollmentPrompt> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/auth/security/mfa/totp/${encodeURIComponent(factorId)}/regenerate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input ?? {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to rotate authenticator');
  }
  return res.json() as Promise<SecurityMfaEnrollmentPrompt>;
}

export async function enableMfaFactor(factorId: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/auth/security/mfa/${encodeURIComponent(factorId)}/enable`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to enable factor');
  }
}

export async function disableMfaFactor(factorId: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/auth/security/mfa/${encodeURIComponent(factorId)}/disable`, {
    method: 'POST',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to disable factor');
  }
}

export async function deleteMfaFactor(factorId: string): Promise<void> {
  const csrf = await getCsrfToken();
  const res = await fetch(`/auth/security/mfa/${encodeURIComponent(factorId)}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to delete factor');
  }
}

export async function regenerateRecoveryCodes(factorId?: string): Promise<{ codes: string[]; expiresAt?: string | null }> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/mfa/backup-codes/regenerate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(factorId ? { factorId } : {}),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to regenerate codes');
  }
  const data = await res.json().catch(() => ({}));
  const record = data && typeof data === 'object' ? (data as Record<string, unknown>) : {};
  const codesRaw = Array.isArray(record.codes) ? record.codes : [];
  const codes = codesRaw.filter((entry): entry is string => typeof entry === 'string');
  const expiresAt = typeof record.expiresAt === 'string' ? record.expiresAt : null;
  return { codes, expiresAt };
}

export async function updateSecurityAlertPreferences(input: SecurityAlertSettings): Promise<SecurityAlertSettings> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/alerts', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to update alerts');
  }
  const data = await res.json().catch(() => ({}));
  const payload = data && typeof data === 'object' && 'alerts' in data
    ? (data as Record<string, unknown>).alerts as Record<string, unknown>
    : (data as Record<string, unknown> | null | undefined);
  const normalized = normalizeAccountSecuritySnapshot({ alerts: payload } as Record<string, unknown>);
  return normalized.alerts;
}

export async function updateSecurityRecoveryContacts(input: SecurityRecoverySettings): Promise<SecurityRecoverySettings> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/security/recovery', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to update recovery settings');
  }
  const data = await res.json().catch(() => ({}));
  const payload = data && typeof data === 'object' && 'recovery' in data
    ? (data as Record<string, unknown>).recovery as Record<string, unknown>
    : (data as Record<string, unknown> | null | undefined);
  const normalized = normalizeAccountSecuritySnapshot({ recovery: payload } as Record<string, unknown>);
  return normalized.recovery;
}

// ----------------------
// Notifications API
// ----------------------

export async function fetchNotificationSettings(): Promise<NotificationSettings> {
  const res = await fetch('/auth/notifications', { credentials: 'include' });
  if (!res.ok) throw new Error('Failed to load notification settings');
  const data = await res.json().catch(() => ({}));
  const payload = data && typeof data === 'object' && 'settings' in data ? (data as Record<string, unknown>).settings : data;
  return normalizeNotificationSettings(payload as Record<string, unknown> | null | undefined);
}

export async function updateNotificationSettings(input: NotificationSettingsInput): Promise<NotificationSettings> {
  const csrf = await getCsrfToken();
  const res = await fetch('/auth/notifications', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to update notifications');
  }
  const data = await res.json().catch(() => ({}));
  const payload = data && typeof data === 'object' && 'settings' in data ? (data as Record<string, unknown>).settings : data;
  return normalizeNotificationSettings(payload as Record<string, unknown> | null | undefined);
}

export async function registerNotificationDevice(input: NotificationDeviceRegistrationInput): Promise<NotificationDevice> {
  const csrf = await getCsrfToken()
  const res = await fetch('/auth/notifications/devices/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to register device')
  }
  const data = await res.json().catch(() => ({}))
  const payload = data && typeof data === 'object' && 'device' in data
    ? (data as Record<string, unknown>).device
    : data
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid device response')
  }
  return payload as NotificationDevice
}

export async function disableNotificationDevice(deviceId: string): Promise<void> {
  const csrf = await getCsrfToken()
  const res = await fetch(`/auth/notifications/devices/${encodeURIComponent(deviceId)}`, {
    method: 'DELETE',
    headers: { 'X-CSRF-Token': csrf },
    credentials: 'include',
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(typeof err?.error === 'string' ? err.error : 'Failed to disable device')
  }
}
