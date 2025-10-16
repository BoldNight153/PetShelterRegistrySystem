// Minimal API client for auth with CSRF double-submit and cookie-based session
export type LoginInput = { email: string; password: string };
export type RegisterInput = { email: string; password: string; name?: string };

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
  return res.json();
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
  const csrf = await getCsrfToken();
  const res = await fetch(`${API_BASE}auth/refresh`, {
    method: "POST",
    headers: { "X-CSRF-Token": csrf },
    credentials: "include",
  });
  if (!res.ok) return null;
  return res.json();
}

// ----------------------
// Admin Settings API
// ----------------------

// Minimal JSON value type for settings
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type SettingsMap = Record<string, Record<string, JsonValue>>;

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

export type Role = { id: string; name: string; rank: number; description?: string | null };
export type Permission = { id: string; name: string; description?: string | null };
export type UserSummary = { id: string; email: string; name?: string | null; roles: string[] };

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

export async function searchUsers(q?: string, page = 1, pageSize = 20): Promise<{ items: UserSummary[]; total: number; page: number; pageSize: number }> {
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
