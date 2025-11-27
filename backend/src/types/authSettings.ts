import type { Prisma } from '@prisma/client';
import {
  DEFAULT_AUTHENTICATOR_CATALOG,
  DEFAULT_ENABLED_AUTHENTICATOR_IDS,
} from '@petshelter/authenticator-catalog';

export type AuthLoginMode = 'session' | 'jwt';
export type AuthMfaPolicy = 'optional' | 'recommended' | 'required';

export type AuthenticatorId = string;

export const DEFAULT_ENABLED_AUTHENTICATORS: AuthenticatorId[] = [...DEFAULT_ENABLED_AUTHENTICATOR_IDS];

export type AuthSettings = {
  mode: AuthLoginMode;
  google: boolean;
  github: boolean;
  enforceMfa: AuthMfaPolicy;
  authenticators: AuthenticatorId[];
};

export const DEFAULT_AUTH_SETTINGS: AuthSettings = {
  mode: 'session',
  google: true,
  github: true,
  enforceMfa: 'recommended',
  authenticators: [...DEFAULT_ENABLED_AUTHENTICATORS, 'backup_codes'],
};

type MaybeRecord = Record<string, unknown> | null | undefined;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }
  return value as Record<string, unknown>;
}

function coerceBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const lowered = value.trim().toLowerCase();
    if (lowered === 'true') return true;
    if (lowered === 'false') return false;
  }
  return fallback;
}

function coerceMode(value: unknown): AuthLoginMode {
  return value === 'jwt' ? 'jwt' : 'session';
}

function coercePolicy(value: unknown): AuthMfaPolicy {
  return value === 'required' || value === 'optional' ? value : 'recommended';
}

type NormalizeAuthenticatorOptions = {
  preserveUnknown?: boolean;
};

export function normalizeAuthenticatorIds(
  input: unknown,
  allowedIds: AuthenticatorId[] = DEFAULT_AUTHENTICATOR_CATALOG.map(entry => entry.id),
  fallback: AuthenticatorId[] = DEFAULT_ENABLED_AUTHENTICATORS,
  options?: NormalizeAuthenticatorOptions,
): AuthenticatorId[] {
  const values: string[] = Array.isArray(input)
    ? input.map(entry => (typeof entry === 'string' ? entry : String(entry ?? '')))
    : typeof input === 'string'
      ? input.split(',')
      : [];
  const allowedSet = new Set(allowedIds);
  const seen = new Set<string>();
  const normalized: AuthenticatorId[] = [];
  for (const raw of values) {
    const id = raw.trim();
    if (!id || seen.has(id)) continue;
    if (allowedSet.has(id)) {
      normalized.push(id);
      seen.add(id);
      continue;
    }
    if (options?.preserveUnknown) {
      normalized.push(id);
      seen.add(id);
    }
  }
  const fallbackSource = fallback.length ? fallback : allowedIds;
  return normalized.length ? normalized : [...fallbackSource];
}

type NormalizeOptions = {
  allowedAuthenticatorIds?: AuthenticatorId[];
  fallbackAuthenticators?: AuthenticatorId[];
  preserveUnknown?: boolean;
};

export function normalizeAuthSettings(value?: MaybeRecord | Prisma.JsonValue, options?: NormalizeOptions): AuthSettings {
  const record = asRecord(value as MaybeRecord);
  const allowed = options?.allowedAuthenticatorIds && options.allowedAuthenticatorIds.length
    ? options.allowedAuthenticatorIds
    : DEFAULT_AUTHENTICATOR_CATALOG.map(entry => entry.id);
  const fallback = options?.fallbackAuthenticators && options.fallbackAuthenticators.length
    ? options.fallbackAuthenticators
    : DEFAULT_AUTH_SETTINGS.authenticators;
  return {
    mode: coerceMode(record?.mode),
    google: coerceBoolean(record?.google, DEFAULT_AUTH_SETTINGS.google),
    github: coerceBoolean(record?.github, DEFAULT_AUTH_SETTINGS.github),
    enforceMfa: coercePolicy(record?.enforceMfa),
    authenticators: normalizeAuthenticatorIds(record?.authenticators, allowed, fallback, {
      preserveUnknown: options?.preserveUnknown,
    }),
  } satisfies AuthSettings;
}

export function normalizeAuthSettingEntry(key: string, value: unknown, options?: NormalizeOptions): unknown {
  const allowed = options?.allowedAuthenticatorIds && options.allowedAuthenticatorIds.length
    ? options.allowedAuthenticatorIds
    : DEFAULT_AUTHENTICATOR_CATALOG.map(entry => entry.id);
  const fallback = options?.fallbackAuthenticators && options.fallbackAuthenticators.length
    ? options.fallbackAuthenticators
    : DEFAULT_AUTH_SETTINGS.authenticators;
  switch (key) {
    case 'mode':
      return coerceMode(value);
    case 'google':
      return coerceBoolean(value, DEFAULT_AUTH_SETTINGS.google);
    case 'github':
      return coerceBoolean(value, DEFAULT_AUTH_SETTINGS.github);
    case 'enforceMfa':
      return coercePolicy(value);
    case 'authenticators':
      return normalizeAuthenticatorIds(value, allowed, fallback, {
        preserveUnknown: options?.preserveUnknown,
      });
    default:
      return value;
  }
}
