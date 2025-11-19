export type AuditRetentionSettings = {
  hotTierDays: number
  coldTierDays: number
  purgeAfterDays: number
  legalHoldContacts: string[]
}

export type AuditExportSettings = {
  defaultFormat: 'csv' | 'json' | 'parquet'
  maxRows: number
  requireApproval: boolean
  approvalRoles: string[]
  watermark: boolean
  autoExpireHours: number
}

export type AuditReviewerSettings = {
  primary: string[]
  backup: string[]
  escalationHours: number
  standbyChannel: string
}

export type AuditAlertChannels = {
  email: boolean
  slack: boolean
  pager: boolean
  sms: boolean
}

export type AuditSeverityRecipients = {
  info: string[]
  warning: string[]
  critical: string[]
}

export type AuditWebhookTarget = {
  id: string
  name: string
  url: string
  secret?: string | null
  events: string[]
  enabled: boolean
}

export type AuditAlertSettings = {
  channels: AuditAlertChannels
  severityRecipients: AuditSeverityRecipients
  webhooks: AuditWebhookTarget[]
  notifyOn: {
    exportRequested: boolean
    exportApproved: boolean
    reviewerBreach: boolean
  }
}

export type AuditSettingsShape = {
  retention: AuditRetentionSettings
  exports: AuditExportSettings
  alerts: AuditAlertSettings
  reviewers: AuditReviewerSettings
}

export const DEFAULT_AUDIT_RETENTION: AuditRetentionSettings = {
  hotTierDays: 90,
  coldTierDays: 365,
  purgeAfterDays: 545,
  legalHoldContacts: ['compliance@example.com'],
}

export const DEFAULT_AUDIT_EXPORTS: AuditExportSettings = {
  defaultFormat: 'csv',
  maxRows: 10000,
  requireApproval: true,
  approvalRoles: ['system_admin', 'audit.reviewer'],
  watermark: true,
  autoExpireHours: 72,
}

export const DEFAULT_AUDIT_REVIEWERS: AuditReviewerSettings = {
  primary: ['security.oncall@example.com'],
  backup: ['compliance@example.com'],
  escalationHours: 4,
  standbyChannel: 'pagerduty://audit',
}

export const DEFAULT_AUDIT_ALERTS: AuditAlertSettings = {
  channels: {
    email: true,
    slack: true,
    pager: true,
    sms: false,
  },
  severityRecipients: {
    info: ['security-announce@example.com'],
    warning: ['security-oncall@example.com'],
    critical: ['security-director@example.com', 'ciso@example.com'],
  },
  webhooks: [
    {
      id: 'ops-slack',
      name: 'Slack :: #audit-stream',
      url: 'https://hooks.slack.com/services/T000/B000/secret',
      secret: null,
      events: ['auth.lock', 'admin.settings', 'audit.export.requested'],
      enabled: true,
    },
  ],
  notifyOn: {
    exportRequested: true,
    exportApproved: true,
    reviewerBreach: true,
  },
}

export const DEFAULT_AUDIT_SETTINGS: AuditSettingsShape = {
  retention: DEFAULT_AUDIT_RETENTION,
  exports: DEFAULT_AUDIT_EXPORTS,
  alerts: DEFAULT_AUDIT_ALERTS,
  reviewers: DEFAULT_AUDIT_REVIEWERS,
}

function coerceNumber(value: unknown, fallback: number): number {
  const num = Number(value)
  return Number.isFinite(num) ? num : fallback
}

function coerceBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}

function coerceString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function coerceStringArray(value: unknown, fallback: string[]): string[] {
  if (Array.isArray(value)) {
    return value
      .map((entry) => (typeof entry === 'string' ? entry : String(entry ?? '')))
      .map((entry) => entry.trim())
      .filter(Boolean)
  }
  if (typeof value === 'string') {
    return value
      .split(/,|\n/)
      .map((entry) => entry.trim())
      .filter(Boolean)
  }
  return [...fallback]
}

function mapWebhook(value: unknown, fallbackId: string): AuditWebhookTarget {
  if (!value || typeof value !== 'object') {
    return {
      id: fallbackId,
      name: 'Webhook',
      url: '',
      secret: null,
      events: ['auth.lock'],
      enabled: true,
    }
  }
  const record = value as Record<string, unknown>
  return {
    id: coerceString(record.id, fallbackId) || fallbackId,
    name: coerceString(record.name, 'Webhook'),
    url: coerceString(record.url, ''),
    secret: typeof record.secret === 'string' ? record.secret : null,
    events: coerceStringArray(record.events, ['auth.lock']),
    enabled: coerceBoolean(record.enabled, true),
  }
}

export function normalizeAuditRetention(value?: unknown): AuditRetentionSettings {
  if (!value || typeof value !== 'object') return { ...DEFAULT_AUDIT_RETENTION }
  const record = value as Record<string, unknown>
  return {
    hotTierDays: coerceNumber(record.hotTierDays, DEFAULT_AUDIT_RETENTION.hotTierDays),
    coldTierDays: coerceNumber(record.coldTierDays, DEFAULT_AUDIT_RETENTION.coldTierDays),
    purgeAfterDays: coerceNumber(record.purgeAfterDays, DEFAULT_AUDIT_RETENTION.purgeAfterDays),
    legalHoldContacts: coerceStringArray(record.legalHoldContacts, DEFAULT_AUDIT_RETENTION.legalHoldContacts),
  }
}

export function normalizeAuditExports(value?: unknown): AuditExportSettings {
  if (!value || typeof value !== 'object') return { ...DEFAULT_AUDIT_EXPORTS }
  const record = value as Record<string, unknown>
  const fmt = record.defaultFormat
  const defaultFormat = fmt === 'json' || fmt === 'parquet' ? fmt : 'csv'
  return {
    defaultFormat,
    maxRows: coerceNumber(record.maxRows, DEFAULT_AUDIT_EXPORTS.maxRows),
    requireApproval: coerceBoolean(record.requireApproval, DEFAULT_AUDIT_EXPORTS.requireApproval),
    approvalRoles: coerceStringArray(record.approvalRoles, DEFAULT_AUDIT_EXPORTS.approvalRoles),
    watermark: coerceBoolean(record.watermark, DEFAULT_AUDIT_EXPORTS.watermark),
    autoExpireHours: coerceNumber(record.autoExpireHours, DEFAULT_AUDIT_EXPORTS.autoExpireHours),
  }
}

export function normalizeAuditReviewers(value?: unknown): AuditReviewerSettings {
  if (!value || typeof value !== 'object') return { ...DEFAULT_AUDIT_REVIEWERS }
  const record = value as Record<string, unknown>
  return {
    primary: coerceStringArray(record.primary, DEFAULT_AUDIT_REVIEWERS.primary),
    backup: coerceStringArray(record.backup, DEFAULT_AUDIT_REVIEWERS.backup),
    escalationHours: coerceNumber(record.escalationHours, DEFAULT_AUDIT_REVIEWERS.escalationHours),
    standbyChannel: coerceString(record.standbyChannel, DEFAULT_AUDIT_REVIEWERS.standbyChannel),
  }
}

export function normalizeAuditAlerts(value?: unknown): AuditAlertSettings {
  if (!value || typeof value !== 'object') return { ...DEFAULT_AUDIT_ALERTS }
  const record = value as Record<string, unknown>
  const channelsRaw = record.channels as Record<string, unknown> | undefined
  const severityRaw = record.severityRecipients as Record<string, unknown> | undefined
  const notifyRaw = record.notifyOn as Record<string, unknown> | undefined
  return {
    channels: {
      email: coerceBoolean(channelsRaw?.email, DEFAULT_AUDIT_ALERTS.channels.email),
      slack: coerceBoolean(channelsRaw?.slack, DEFAULT_AUDIT_ALERTS.channels.slack),
      pager: coerceBoolean(channelsRaw?.pager, DEFAULT_AUDIT_ALERTS.channels.pager),
      sms: coerceBoolean(channelsRaw?.sms, DEFAULT_AUDIT_ALERTS.channels.sms),
    },
    severityRecipients: {
      info: coerceStringArray(severityRaw?.info, DEFAULT_AUDIT_ALERTS.severityRecipients.info),
      warning: coerceStringArray(severityRaw?.warning, DEFAULT_AUDIT_ALERTS.severityRecipients.warning),
      critical: coerceStringArray(severityRaw?.critical, DEFAULT_AUDIT_ALERTS.severityRecipients.critical),
    },
    webhooks: Array.isArray(record.webhooks)
      ? record.webhooks.map((item, index) => mapWebhook(item, `audit-webhook-${index + 1}`))
      : DEFAULT_AUDIT_ALERTS.webhooks.map((item) => ({ ...item })),
    notifyOn: {
      exportRequested: coerceBoolean(notifyRaw?.exportRequested, DEFAULT_AUDIT_ALERTS.notifyOn.exportRequested),
      exportApproved: coerceBoolean(notifyRaw?.exportApproved, DEFAULT_AUDIT_ALERTS.notifyOn.exportApproved),
      reviewerBreach: coerceBoolean(notifyRaw?.reviewerBreach, DEFAULT_AUDIT_ALERTS.notifyOn.reviewerBreach),
    },
  }
}

export function normalizeAuditSettings(value?: Record<string, unknown> | null | undefined): AuditSettingsShape {
  const source = value ?? {}
  return {
    retention: normalizeAuditRetention(source.retention),
    exports: normalizeAuditExports(source.exports),
    alerts: normalizeAuditAlerts(source.alerts),
    reviewers: normalizeAuditReviewers(source.reviewers),
  }
}
