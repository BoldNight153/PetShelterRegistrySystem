export type NotificationChannel = 'email' | 'sms' | 'push' | 'in_app';
export type NotificationTopicCategory = 'account' | 'animals' | 'operations' | 'security' | 'system';
export type NotificationDigestFrequency = 'daily' | 'weekly';
export type NotificationDevicePlatform = 'ios' | 'android' | 'web' | 'unknown';

export type NotificationTopicPreference = {
  id: string;
  label: string;
  description?: string | null;
  category: NotificationTopicCategory;
  enabled: boolean;
  channels: NotificationChannel[];
  critical?: boolean;
  muteUntil?: string | null;
};

export type NotificationTopicPreferenceInput = Partial<Omit<NotificationTopicPreference, 'id'>> & { id: string };

export type NotificationDigestSettings = {
  enabled: boolean;
  frequency: NotificationDigestFrequency;
  sendHourLocal: number;
  timezone?: string | null;
  includeSummary: boolean;
};

export type NotificationQuietHours = {
  enabled: boolean;
  startHour: number;
  endHour: number;
  timezone?: string | null;
};

export type NotificationCriticalEscalations = {
  smsFallback: boolean;
  backupEmail?: string | null;
  pagerDutyWebhook?: string | null;
};

export type NotificationDevice = {
  id: string;
  label: string;
  platform: NotificationDevicePlatform;
  enabled: boolean;
  lastUsedAt?: string | null;
};

export type NotificationSettings = {
  defaultChannels: NotificationChannel[];
  topics: NotificationTopicPreference[];
  digests: NotificationDigestSettings;
  quietHours: NotificationQuietHours;
  criticalEscalations: NotificationCriticalEscalations;
  devices: NotificationDevice[];
};

export type NotificationSettingsInput = Partial<Omit<NotificationSettings, 'topics' | 'devices'>> & {
  topics?: NotificationTopicPreferenceInput[];
  devices?: NotificationDevice[];
};

const CHANNELS: NotificationChannel[] = ['email', 'sms', 'push', 'in_app'];
const TOPIC_CATEGORIES: NotificationTopicCategory[] = ['account', 'animals', 'operations', 'security', 'system'];

const DEFAULT_DIGEST: NotificationDigestSettings = {
  enabled: true,
  frequency: 'weekly',
  sendHourLocal: 8,
  timezone: 'UTC',
  includeSummary: true,
};

const DEFAULT_QUIET_HOURS: NotificationQuietHours = {
  enabled: false,
  startHour: 22,
  endHour: 7,
  timezone: 'UTC',
};

const DEFAULT_ESCALATIONS: NotificationCriticalEscalations = {
  smsFallback: true,
  backupEmail: null,
  pagerDutyWebhook: null,
};

const DEFAULT_TOPICS: NotificationTopicPreference[] = [
  {
    id: 'security_login_alerts',
    label: 'Security: Sign-in alerts',
    description: 'Successful logins, new devices, and MFA changes.',
    category: 'security',
    enabled: true,
    channels: ['email'],
    critical: true,
  },
  {
    id: 'system_incidents',
    label: 'System incidents',
    description: 'Major uptime or reliability issues.',
    category: 'system',
    enabled: true,
    channels: ['email', 'sms'],
    critical: true,
  },
  {
    id: 'task_assignments',
    label: 'Task assignments',
    description: 'When new tasks or follow-ups are assigned to you.',
    category: 'operations',
    enabled: true,
    channels: ['email', 'push'],
  },
  {
    id: 'animal_matches',
    label: 'Animal matches & updates',
    description: 'New fosters, adopters, or status changes for your animals.',
    category: 'animals',
    enabled: true,
    channels: ['email'],
  },
  {
    id: 'daily_digest',
    label: 'Daily digest',
    description: 'Summary of assignments, events, and reminders.',
    category: 'account',
    enabled: true,
    channels: ['email'],
  },
];

export const DEFAULT_NOTIFICATION_SETTINGS: NotificationSettings = {
  defaultChannels: ['email'],
  topics: DEFAULT_TOPICS.map((topic) => cloneTopic(topic)),
  digests: { ...DEFAULT_DIGEST },
  quietHours: { ...DEFAULT_QUIET_HOURS },
  criticalEscalations: { ...DEFAULT_ESCALATIONS },
  devices: [],
};

export function normalizeNotificationSettings(value?: Record<string, unknown> | null): NotificationSettings {
  const base = cloneDefaultSettings();
  if (!value || typeof value !== 'object') {
    return base;
  }
  const record = value as Record<string, unknown>;
  return {
    defaultChannels: coerceChannelList(record.defaultChannels, base.defaultChannels),
    topics: normalizeTopics(record.topics, base.topics),
    digests: normalizeDigest(record.digests, base.digests),
    quietHours: normalizeQuietHours(record.quietHours, base.quietHours),
    criticalEscalations: normalizeEscalations(record.criticalEscalations, base.criticalEscalations),
    devices: normalizeDevices(record.devices, base.devices),
  };
}

function normalizeTopics(value: unknown, fallback: NotificationTopicPreference[]): NotificationTopicPreference[] {
  const byId = new Map<string, NotificationTopicPreference>();
  fallback.forEach((topic) => byId.set(topic.id, cloneTopic(topic)));

  if (!Array.isArray(value)) {
    return Array.from(byId.values());
  }

  for (const entry of value) {
    const id = extractTopicId(entry);
    const existing = id ? byId.get(id) : undefined;
    const normalized = normalizeTopic(entry, existing);
    if (!normalized) continue;
    byId.set(normalized.id, normalized);
  }

  return Array.from(byId.values());
}

function normalizeTopic(value: unknown, fallback?: NotificationTopicPreference): NotificationTopicPreference | null {
  if (!value || typeof value !== 'object') {
    return fallback ? cloneTopic(fallback) : null;
  }
  const record = value as Record<string, unknown>;
  const id = coerceString(record.id, fallback?.id ?? '');
  if (!id) return fallback ? cloneTopic(fallback) : null;
  const base = fallback ? cloneTopic(fallback) : undefined;
  return {
    id,
    label: coerceString(record.label, base?.label ?? id),
    description: coerceNullableString(record.description, base?.description ?? null),
    category: coerceCategory(record.category, base?.category ?? 'account'),
    enabled: coerceBoolean(record.enabled, base?.enabled ?? true),
    channels: coerceChannelList(record.channels, base?.channels ?? ['email']),
    critical: coerceBoolean(record.critical, base?.critical ?? false),
    muteUntil: coerceDate(record.muteUntil),
  };
}

function normalizeDigest(value: unknown, fallback: NotificationDigestSettings): NotificationDigestSettings {
  if (!value || typeof value !== 'object') return { ...fallback };
  const record = value as Record<string, unknown>;
  const frequency = record.frequency === 'daily' || record.frequency === 'weekly' ? record.frequency : fallback.frequency;
  return {
    enabled: coerceBoolean(record.enabled, fallback.enabled),
    frequency,
    sendHourLocal: coerceNumber(record.sendHourLocal, fallback.sendHourLocal, 0, 23),
    timezone: coerceNullableString(record.timezone, fallback.timezone ?? null),
    includeSummary: coerceBoolean(record.includeSummary, fallback.includeSummary),
  };
}

function normalizeQuietHours(value: unknown, fallback: NotificationQuietHours): NotificationQuietHours {
  if (!value || typeof value !== 'object') return { ...fallback };
  const record = value as Record<string, unknown>;
  return {
    enabled: coerceBoolean(record.enabled, fallback.enabled),
    startHour: coerceNumber(record.startHour, fallback.startHour, 0, 23),
    endHour: coerceNumber(record.endHour, fallback.endHour, 0, 23),
    timezone: coerceNullableString(record.timezone, fallback.timezone ?? null),
  };
}

function normalizeEscalations(value: unknown, fallback: NotificationCriticalEscalations): NotificationCriticalEscalations {
  if (!value || typeof value !== 'object') return { ...fallback };
  const record = value as Record<string, unknown>;
  return {
    smsFallback: coerceBoolean(record.smsFallback, fallback.smsFallback),
    backupEmail: coerceEmail(record.backupEmail, fallback.backupEmail ?? null),
    pagerDutyWebhook: coerceUrl(record.pagerDutyWebhook, fallback.pagerDutyWebhook ?? null),
  };
}

function normalizeDevices(value: unknown, fallback: NotificationDevice[]): NotificationDevice[] {
  if (!Array.isArray(value)) return fallback.map((device) => cloneDevice(device));
  const devices: NotificationDevice[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== 'object') continue;
    const record = entry as Record<string, unknown>;
    const id = coerceString(record.id);
    if (!id) continue;
    devices.push({
      id,
      label: coerceString(record.label, 'Unnamed device'),
      platform: coercePlatform(record.platform),
      enabled: coerceBoolean(record.enabled, true),
      lastUsedAt: coerceDate(record.lastUsedAt),
    });
  }
  return devices.slice(0, 25);
}

function extractTopicId(value: unknown): string {
  if (!value || typeof value !== 'object') return '';
  const record = value as Record<string, unknown>;
  return coerceString(record.id, '');
}

function coerceChannelList(value: unknown, fallback: NotificationChannel[]): NotificationChannel[] {
  if (!Array.isArray(value)) return [...fallback];
  const list = value
    .map((entry) => (typeof entry === 'string' ? entry : null))
    .filter((entry): entry is string => Boolean(entry))
    .map((entry) => (CHANNELS.includes(entry as NotificationChannel) ? (entry as NotificationChannel) : 'email'));
  const unique = Array.from(new Set(list));
  return unique.length ? unique : [...fallback];
}

function coerceBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value === 'boolean') return value;
  if (value === 'true') return true;
  if (value === 'false') return false;
  return fallback;
}

function coerceNumber(value: unknown, fallback: number, min?: number, max?: number): number {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  let next = num;
  if (typeof min === 'number') next = Math.max(min, next);
  if (typeof max === 'number') next = Math.min(max, next);
  return next;
}

function coerceString(value: unknown, fallback = ''): string {
  if (typeof value === 'string' && value.trim().length) return value.trim();
  if (typeof value === 'number') return String(value);
  return fallback;
}

function coerceNullableString(value: unknown, fallback: string | null): string | null {
  if (value == null) return null;
  const str = coerceString(value, '');
  if (!str.length) return fallback;
  return str;
}

function coerceCategory(value: unknown, fallback: NotificationTopicCategory): NotificationTopicCategory {
  if (typeof value !== 'string') return fallback;
  const normalized = value.toLowerCase();
  return TOPIC_CATEGORIES.includes(normalized as NotificationTopicCategory)
    ? (normalized as NotificationTopicCategory)
    : fallback;
}

function coerceDate(value: unknown): string | null {
  if (typeof value === 'string' && value.trim().length) return value;
  if (value instanceof Date) return value.toISOString();
  return null;
}

function coerceEmail(value: unknown, fallback: string | null): string | null {
  const str = coerceNullableString(value, fallback ?? null);
  if (!str) return fallback ?? null;
  return /.+@.+/i.test(str) ? str : fallback ?? null;
}

function coerceUrl(value: unknown, fallback: string | null): string | null {
  const str = coerceNullableString(value, fallback ?? null);
  if (!str) return fallback ?? null;
  try {
    new URL(str);
    return str;
  } catch {
    return fallback ?? null;
  }
}

function coercePlatform(value: unknown): NotificationDevicePlatform {
  if (value === 'ios' || value === 'android' || value === 'web' || value === 'unknown') {
    return value;
  }
  return 'unknown';
}

function cloneTopic(topic: NotificationTopicPreference): NotificationTopicPreference {
  return { ...topic, channels: [...topic.channels] };
}

function cloneDevice(device: NotificationDevice): NotificationDevice {
  return { ...device };
}

function cloneDefaultSettings(): NotificationSettings {
  return {
    defaultChannels: [...DEFAULT_NOTIFICATION_SETTINGS.defaultChannels],
    topics: DEFAULT_NOTIFICATION_SETTINGS.topics.map((topic) => cloneTopic(topic)),
    digests: { ...DEFAULT_NOTIFICATION_SETTINGS.digests },
    quietHours: { ...DEFAULT_NOTIFICATION_SETTINGS.quietHours },
    criticalEscalations: { ...DEFAULT_NOTIFICATION_SETTINGS.criticalEscalations },
    devices: [],
  };
}
