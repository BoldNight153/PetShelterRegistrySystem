// Minimal API client for auth with CSRF double-submit and cookie-based session
type LoginInput = { email: string; password: string };
type RegisterInput = { email: string; password: string; name?: string };

const API_BASE = "/"; // Vite proxy should send /auth to backend

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
    const msg = typeof err?.error === 'string' ? err.error : (err?.error?.message || null);
    throw new Error(msg || `Login failed (${res.status})`);
  }
  const body = await res.json();

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
