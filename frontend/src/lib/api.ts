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
