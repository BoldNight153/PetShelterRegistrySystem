// Centralized shared types for services (decoupled from runtime API module)
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type SettingsMap = Record<string, Record<string, JsonValue>>;

export type Role = { id: string; name: string; rank: number; description?: string | null };
export type Permission = { id: string; name: string; description?: string | null };
export type UserSummary = { id: string; email: string; name?: string | null; roles: string[] };
export type UserSummaryWithLock = UserSummary & { lock: { reason: string; until: string | null } | null };

export type UserDetail = UserSummaryWithLock & {
  image?: string | null;
  permissions?: string[];
  createdAt?: string | null;
  lastLoginAt?: string | null;
  updatedAt?: string | null;
  metadata?: Record<string, unknown> | null;
};

export type Page<T> = { items: T[]; total: number; page: number; pageSize: number };

export type AuditSeverity = 'info' | 'warning' | 'critical';

export type AuditActor = {
  id?: string | null;
  name?: string | null;
  email?: string | null;
  initials?: string | null;
};

export type AuditTarget = {
  type: string;
  id?: string | null;
  label?: string | null;
};

export type AuditTimelineEntry = {
  id: string;
  action: string;
  createdAt: string;
  description: string;
  severity: AuditSeverity;
  actor: AuditActor;
  target?: AuditTarget;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: JsonValue;
  tags: string[];
};

export type UserProfileUpdateInput = {
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
