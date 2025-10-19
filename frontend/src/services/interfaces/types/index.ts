// Centralized shared types for services (decoupled from runtime API module)
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type SettingsMap = Record<string, Record<string, JsonValue>>;

export type Role = { id: string; name: string; rank: number; description?: string | null };
export type Permission = { id: string; name: string; description?: string | null };
export type UserSummary = { id: string; email: string; name?: string | null; roles: string[] };
export type UserSummaryWithLock = UserSummary & { lock: { reason: string; until: string | null } | null };

export type UserDetail = UserSummaryWithLock & {
  createdAt?: string | null;
  lastLoginAt?: string | null;
  metadata?: Record<string, unknown> | null;
};
