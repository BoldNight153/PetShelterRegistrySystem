import { PrismaClient, Prisma } from '@prisma/client';
import type { NotificationDeviceRegistration } from '@prisma/client';
import {
  type NotificationSettings,
  type NotificationSettingsInput,
  type NotificationTopicPreference,
  type NotificationDigestSettings,
  type NotificationQuietHours,
  type NotificationCriticalEscalations,
  type NotificationDevice,
  type NotificationChannel,
  type NotificationTopicCategory,
  type NotificationDeviceRegistrationInput,
} from '../types/notificationSettings';
import type { INotificationService } from './interfaces/notificationService.interface';

export type NotificationPrisma = Pick<PrismaClient, 'user' | 'notificationDeviceRegistration'>;

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

export function createDefaultNotificationSettings(): NotificationSettings {
  return {
    defaultChannels: ['email'],
    topics: DEFAULT_TOPICS.map(topic => ({ ...topic, channels: [...topic.channels] })),
    digests: { ...DEFAULT_DIGEST },
    quietHours: { ...DEFAULT_QUIET_HOURS },
    criticalEscalations: { ...DEFAULT_ESCALATIONS },
    devices: [],
  };
}

export class NotificationService implements INotificationService {
  private prisma: NotificationPrisma;

  constructor(opts?: { prisma?: NotificationPrisma }) {
    this.prisma = opts?.prisma ?? new PrismaClient();
  }

  async getNotificationSettings(userId: string): Promise<NotificationSettings | null> {
    const user = await this.prisma.user.findUnique({ where: { id: userId }, include: { notificationDevices: true } });
    if (!user) return null;
    const metadata = this.asRecord((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const raw = metadata?.notifications ?? null;
    const settings = this.normalizeSettings(raw, metadata ?? null);
    const registered = this.mapDeviceRegistrations(((user as any)?.notificationDevices ?? []) as NotificationDeviceRegistration[]);
    if (registered.length) {
      settings.devices = registered;
    }
    return settings;
  }

  async updateNotificationSettings(userId: string, payload: NotificationSettingsInput): Promise<NotificationSettings | null> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return null;

    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const current = this.normalizeSettings(metadata.notifications ?? null, metadata);
    const sanitizedPayload: NotificationSettingsInput = { ...payload };
    let devicePatch: NotificationDevice[] | undefined;
    if (Array.isArray(payload.devices)) {
      devicePatch = this.normalizeDevices(payload.devices, current.devices);
      sanitizedPayload.devices = devicePatch;
      await this.updateRegisteredDeviceStatuses(userId, devicePatch);
    }

    const next = this.mergeSettings(current, sanitizedPayload);

    const securityAlerts = this.buildSecurityAlertPayload(next);
    const security = this.asRecord(metadata.security) ?? {};
    if (securityAlerts) {
      security.alerts = securityAlerts;
    }
    metadata.security = security;
    const registeredDevices = await this.fetchRegisteredDevices(userId);
    if (registeredDevices.length) {
      next.devices = registeredDevices;
    }
    metadata.notifications = next;

    await this.prisma.user.update({
      where: { id: userId },
      data: { metadata: metadata as Prisma.JsonObject } as Prisma.UserUpdateInput,
    });

    return next;
  }

  async registerNotificationDevice(userId: string, payload: NotificationDeviceRegistrationInput): Promise<NotificationDevice | null> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return null;

    const label = this.coerceString(payload.label, 'Unnamed device').slice(0, 160) || 'Unnamed device';
    const platform = this.coerceDevicePlatform(payload.platform ?? 'unknown');
    const transport = payload.transport === 'mobile_push' ? 'mobile_push' : 'web_push';
    const fingerprint = this.coerceNullableString(payload.fingerprint, null);
    const token = this.coerceNullableString(payload.token, null);
    const subscriptionValue = payload.subscription ? (payload.subscription as Prisma.InputJsonValue) : Prisma.JsonNull;
    const lookup = [] as Prisma.NotificationDeviceRegistrationWhereInput[];
    if (fingerprint) lookup.push({ fingerprint });
    if (token) lookup.push({ token });
    const existing = lookup.length
      ? await this.prisma.notificationDeviceRegistration.findFirst({ where: { userId, OR: lookup } })
      : null;

    const baseDeviceData = {
      label,
      platform,
      transport,
      fingerprint,
      subscription: subscriptionValue,
      token,
      status: 'active',
      revokedAt: null,
      lastUsedAt: new Date(),
      userAgent: this.coerceNullableString(payload.userAgent, null),
      ipAddress: this.coerceNullableString(payload.ipAddress, null),
    };

    const updatePayload: Prisma.NotificationDeviceRegistrationUncheckedUpdateInput = {
      ...baseDeviceData,
    };

    const createPayload: Prisma.NotificationDeviceRegistrationUncheckedCreateInput = {
      ...baseDeviceData,
      userId,
      registeredAt: new Date(),
    };

    let record: NotificationDeviceRegistration;
    if (existing) {
      record = await this.prisma.notificationDeviceRegistration.update({ where: { id: existing.id }, data: updatePayload });
    } else {
      record = await this.prisma.notificationDeviceRegistration.create({ data: createPayload });
    }

    await this.refreshRegisteredDevicesCache(userId);
    const devices = this.mapDeviceRegistrations([record]);
    return devices[0] ?? null;
  }

  async disableNotificationDevice(userId: string, deviceId: string): Promise<boolean> {
    const existing = await this.prisma.notificationDeviceRegistration.findFirst({ where: { id: deviceId, userId } });
    if (!existing) return false;
    await this.prisma.notificationDeviceRegistration.update({
      where: { id: existing.id },
      data: { status: 'revoked', revokedAt: new Date(), lastUsedAt: new Date() },
    });
    await this.refreshRegisteredDevicesCache(userId);
    return true;
  }

  private normalizeSettings(raw: unknown, metadata: Record<string, any> | null): NotificationSettings {
    const base = createDefaultNotificationSettings();
    const record = this.asRecord(raw);
    if (!record) {
      const securityTopics = this.buildTopicsFromSecurityAlerts(metadata);
      if (securityTopics.length) {
        base.topics = this.mergeTopicArrays(base.topics, securityTopics);
        const defaults = this.extractSecurityDefaultChannels(metadata);
        if (defaults.length) base.defaultChannels = defaults;
      }
      return base;
    }

    return {
      defaultChannels: this.coerceChannelList(record.defaultChannels, base.defaultChannels),
      topics: this.normalizeTopics(record.topics, base.topics),
      digests: this.normalizeDigest(record.digests, base.digests),
      quietHours: this.normalizeQuietHours(record.quietHours, base.quietHours),
      criticalEscalations: this.normalizeEscalations(record.criticalEscalations, base.criticalEscalations),
      devices: this.normalizeDevices(record.devices, base.devices),
    };
  }

  private mergeSettings(current: NotificationSettings, patch: NotificationSettingsInput): NotificationSettings {
    return {
      defaultChannels: patch.defaultChannels ? this.coerceChannelList(patch.defaultChannels, current.defaultChannels) : [...current.defaultChannels],
      topics: Array.isArray(patch.topics) ? this.normalizeTopics(patch.topics, current.topics) : current.topics.map(topic => this.cloneTopic(topic)),
      digests: patch.digests ? this.normalizeDigest(patch.digests, current.digests) : { ...current.digests },
      quietHours: patch.quietHours ? this.normalizeQuietHours(patch.quietHours, current.quietHours) : { ...current.quietHours },
      criticalEscalations: patch.criticalEscalations ? this.normalizeEscalations(patch.criticalEscalations, current.criticalEscalations) : { ...current.criticalEscalations },
      devices: Array.isArray(patch.devices) ? this.normalizeDevices(patch.devices, current.devices) : current.devices.map(device => ({ ...device })),
    };
  }

  private normalizeTopics(raw: unknown, fallback: NotificationTopicPreference[]): NotificationTopicPreference[] {
    const baseMap = new Map<string, NotificationTopicPreference>();
    fallback.forEach(topic => baseMap.set(topic.id, this.cloneTopic(topic)));

    if (!Array.isArray(raw)) {
      return Array.from(baseMap.values());
    }

    for (const entry of raw) {
      const idCandidate = this.extractTopicId(entry);
      const fallback = idCandidate ? baseMap.get(idCandidate) : undefined;
      const normalized = this.normalizeTopic(entry, fallback);
      if (!normalized) continue;
      baseMap.set(normalized.id, normalized);
    }
    return Array.from(baseMap.values());
  }

  private normalizeTopic(value: unknown, fallback?: NotificationTopicPreference): NotificationTopicPreference | null {
    if (!value || typeof value !== 'object') {
      return fallback ? this.cloneTopic(fallback) : null;
    }
    const record = value as Record<string, unknown>;
    const id = this.coerceString(record.id);
    if (!id) return null;
    const base = fallback ? this.cloneTopic(fallback) : undefined;
    return {
      id,
      label: this.coerceString(record.label, base?.label ?? id),
      description: this.coerceNullableString(record.description, base?.description ?? null),
      category: this.coerceCategory(record.category, base?.category ?? 'account'),
      enabled: this.coerceBoolean(record.enabled, base?.enabled ?? true),
      channels: this.coerceChannelList(record.channels, base?.channels ?? ['email']),
      critical: this.coerceBoolean(record.critical, base?.critical ?? false),
      muteUntil: this.coerceDate(record.muteUntil),
    };
  }

  private normalizeDigest(value: unknown, fallback: NotificationDigestSettings): NotificationDigestSettings {
    if (!value || typeof value !== 'object') return { ...fallback };
    const record = value as Record<string, unknown>;
    const frequency = record.frequency === 'daily' || record.frequency === 'weekly' ? record.frequency : fallback.frequency;
    const sendHour = this.coerceNumber(record.sendHourLocal, fallback.sendHourLocal, 0, 23);
    const timezone = this.coerceNullableString(record.timezone, fallback.timezone ?? null);
    return {
      enabled: this.coerceBoolean(record.enabled, fallback.enabled),
      frequency,
      sendHourLocal: sendHour,
      timezone,
      includeSummary: this.coerceBoolean(record.includeSummary, fallback.includeSummary),
    };
  }

  private normalizeQuietHours(value: unknown, fallback: NotificationQuietHours): NotificationQuietHours {
    if (!value || typeof value !== 'object') return { ...fallback };
    const record = value as Record<string, unknown>;
    return {
      enabled: this.coerceBoolean(record.enabled, fallback.enabled),
      startHour: this.coerceNumber(record.startHour, fallback.startHour, 0, 23),
      endHour: this.coerceNumber(record.endHour, fallback.endHour, 0, 23),
      timezone: this.coerceNullableString(record.timezone, fallback.timezone ?? null),
    };
  }

  private normalizeEscalations(value: unknown, fallback: NotificationCriticalEscalations): NotificationCriticalEscalations {
    if (!value || typeof value !== 'object') return { ...fallback };
    const record = value as Record<string, unknown>;
    return {
      smsFallback: this.coerceBoolean(record.smsFallback, fallback.smsFallback),
      backupEmail: this.coerceNullableEmail(record.backupEmail, fallback.backupEmail ?? null),
      pagerDutyWebhook: this.coerceNullableUrl(record.pagerDutyWebhook, fallback.pagerDutyWebhook ?? null),
    };
  }

  private normalizeDevices(value: unknown, fallback: NotificationDevice[]): NotificationDevice[] {
    if (!Array.isArray(value)) return fallback.map(device => ({ ...device }));
    const devices: NotificationDevice[] = [];
    for (const entry of value) {
      if (!entry || typeof entry !== 'object') continue;
      const record = entry as Record<string, unknown>;
      const id = this.coerceString(record.id);
      if (!id) continue;
      const platform = this.coerceDevicePlatform(record.platform);
      devices.push({
        id,
        label: this.coerceString(record.label, 'Unnamed device'),
        platform,
        enabled: this.coerceBoolean(record.enabled, true),
        lastUsedAt: this.coerceDate(record.lastUsedAt),
      });
    }
    return devices.slice(0, 25);
  }

  private async fetchRegisteredDevices(userId: string): Promise<NotificationDevice[]> {
    const records = await this.prisma.notificationDeviceRegistration.findMany({
      where: { userId },
      orderBy: [{ status: 'desc' }, { updatedAt: 'desc' }],
      take: 25,
    });
    return this.mapDeviceRegistrations(records as NotificationDeviceRegistration[]);
  }

  private mapDeviceRegistrations(records: NotificationDeviceRegistration[]): NotificationDevice[] {
    if (!Array.isArray(records) || !records.length) return [];
    return records.map(record => ({
      id: record.id,
      label: this.coerceString(record.label, 'Unnamed device'),
      platform: this.coerceDevicePlatform(record.platform),
      enabled: record.status !== 'revoked' && record.status !== 'disabled',
      lastUsedAt: record.lastUsedAt ? this.coerceDate(record.lastUsedAt) : (record.updatedAt ? this.coerceDate(record.updatedAt) : null),
    }));
  }

  private async updateRegisteredDeviceStatuses(userId: string, devices: NotificationDevice[]): Promise<void> {
    if (!devices.length) return;
    await Promise.all(devices.map(async device => {
      const lastUsedAt = device.lastUsedAt ? this.parseDate(device.lastUsedAt) : undefined;
      await this.prisma.notificationDeviceRegistration.updateMany({
        where: { id: device.id, userId },
        data: {
          status: device.enabled ? 'active' : 'disabled',
          lastUsedAt,
          revokedAt: device.enabled ? null : undefined,
        },
      });
    }));
  }

  private async refreshRegisteredDevicesCache(userId: string): Promise<NotificationDevice[]> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return [];
    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const normalized = this.normalizeSettings(metadata.notifications ?? null, metadata);
    const devices = await this.fetchRegisteredDevices(userId);
    if (devices.length) {
      normalized.devices = devices;
    }
    metadata.notifications = normalized;
    await this.prisma.user.update({
      where: { id: userId },
      data: { metadata: metadata as Prisma.JsonObject } as Prisma.UserUpdateInput,
    });
    return devices;
  }

  private buildSecurityAlertPayload(settings: NotificationSettings): Record<string, unknown> | null {
    const securityTopics = settings.topics.filter(topic => topic.category === 'security');
    if (!securityTopics.length) return null;
    return {
      preferences: securityTopics.map(topic => ({
        event: topic.id,
        label: topic.label,
        enabled: topic.enabled,
        channels: [...topic.channels],
      })),
      defaultChannels: [...settings.defaultChannels],
    };
  }

  private buildTopicsFromSecurityAlerts(metadata: Record<string, any> | null): NotificationTopicPreference[] {
    if (!metadata) return [];
    const security = this.asRecord(metadata.security);
    const alerts = this.asRecord(security?.alerts);
    const prefs = Array.isArray(alerts?.preferences) ? alerts?.preferences ?? [] : [];
    return prefs.map((pref: any, index: number) => ({
      id: this.coerceString(pref.event, `security_event_${index}`),
      label: this.coerceString(pref.label, 'Security alert'),
      description: 'Migrated from Account Security alerts',
      category: 'security',
      enabled: this.coerceBoolean(pref.enabled, true),
      channels: this.coerceChannelList(pref.channels, ['email']),
      critical: true,
    }));
  }

  private extractTopicId(value: unknown): string {
    if (!value || typeof value !== 'object') return '';
    const record = value as Record<string, unknown>;
    return this.coerceString(record.id, '');
  }

  private mergeTopicArrays(base: NotificationTopicPreference[], updates: NotificationTopicPreference[]): NotificationTopicPreference[] {
    const map = new Map<string, NotificationTopicPreference>();
    base.forEach(topic => map.set(topic.id, this.cloneTopic(topic)));
    updates.forEach(topic => map.set(topic.id, this.cloneTopic(topic)));
    return Array.from(map.values());
  }

  private extractSecurityDefaultChannels(metadata: Record<string, any> | null): NotificationChannel[] {
    if (!metadata) return [];
    const security = this.asRecord(metadata.security);
    const alerts = this.asRecord(security?.alerts);
    if (!alerts) return [];
    return this.coerceChannelList(alerts.defaultChannels, []);
  }

  private cloneTopic(topic: NotificationTopicPreference): NotificationTopicPreference {
    return { ...topic, channels: [...topic.channels] };
  }

  private coerceChannelList(value: unknown, fallback: NotificationChannel[]): NotificationChannel[] {
    const allowed: NotificationChannel[] = ['email', 'sms', 'push', 'in_app'];
    const ensureFallback = (): NotificationChannel[] => {
      const fallbackList: NotificationChannel[] = fallback.length ? [...fallback] : (['email'] as NotificationChannel[]);
      return [...new Set<NotificationChannel>(fallbackList)];
    };
    if (!Array.isArray(value)) {
      return ensureFallback();
    }
    const list = value
      .map(entry => (typeof entry === 'string' ? entry : null))
      .filter((entry): entry is string => Boolean(entry))
      .map(entry => (allowed.includes(entry as NotificationChannel) ? (entry as NotificationChannel) : ('email' as NotificationChannel)));
    const unique = Array.from(new Set<NotificationChannel>(list));
    return unique.length ? unique : ensureFallback();
  }

  private coerceBoolean(value: unknown, fallback: boolean): boolean {
    if (typeof value === 'boolean') return value;
    if (value === 'true') return true;
    if (value === 'false') return false;
    return fallback;
  }

  private coerceNumber(value: unknown, fallback: number, min?: number, max?: number): number {
    const num = Number(value);
    if (!Number.isFinite(num)) return fallback;
    let next = num;
    if (typeof min === 'number') next = Math.max(min, next);
    if (typeof max === 'number') next = Math.min(max, next);
    return next;
  }

  private coerceString(value: unknown, fallback = ''): string {
    if (typeof value === 'string' && value.trim().length) return value.trim();
    if (typeof value === 'number') return String(value);
    return fallback;
  }

  private coerceNullableString(value: unknown, fallback: string | null): string | null {
    if (value == null) return null;
    const str = this.coerceString(value);
    return str.length ? str : fallback;
  }

  private coerceCategory(value: unknown, fallback: NotificationTopicCategory): NotificationTopicCategory {
    if (typeof value !== 'string') return fallback;
    const normalized = value.toLowerCase();
    const allowed: NotificationTopicCategory[] = ['account', 'animals', 'operations', 'security', 'system'];
    return allowed.includes(normalized as NotificationTopicCategory)
      ? (normalized as NotificationTopicCategory)
      : fallback;
  }

  private coerceDate(value: unknown): string | null {
    if (!value) return null;
    const date = value instanceof Date ? value : typeof value === 'string' ? new Date(value) : null;
    if (!date) return null;
    const epoch = date.getTime();
    if (!Number.isFinite(epoch)) return null;
    try {
      return date.toISOString();
    } catch {
      return null;
    }
  }

  private coerceNullableEmail(value: unknown, fallback: string | null): string | null {
    const str = this.coerceNullableString(value, fallback);
    if (!str) return fallback ?? null;
    return /.+@.+/.test(str) ? str : fallback ?? null;
  }

  private coerceNullableUrl(value: unknown, fallback: string | null): string | null {
    const str = this.coerceNullableString(value, fallback);
    if (!str) return fallback ?? null;
    try {
      new URL(str);
      return str;
    } catch {
      return fallback ?? null;
    }
  }

  private coerceDevicePlatform(value: unknown): NotificationDevice['platform'] {
    if (value === 'ios' || value === 'android' || value === 'web' || value === 'unknown') {
      return value;
    }
    return 'unknown';
  }

  private parseDate(value: string | Date | null | undefined): Date | undefined {
    if (!value) return undefined;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isFinite(date.getTime()) ? date : undefined;
  }

  private asRecord(value: unknown): Record<string, any> | null {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    return value as Record<string, any>;
  }

  private cloneMetadata(value: Prisma.JsonValue | null | undefined): Record<string, any> {
    if (!value) return {};
    if (typeof value === 'string') {
      try {
        const parsed = JSON.parse(value);
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return { ...(parsed as Record<string, any>) };
      } catch {
        return {};
      }
      return {};
    }
    if (typeof value === 'object' && !Array.isArray(value)) return { ...(value as Record<string, any>) };
    return {};
  }
}

export default NotificationService;
