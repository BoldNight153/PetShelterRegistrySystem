import type { JsonValue } from '@/services/interfaces/types'

export type SecurityRiskSeverity = 'info' | 'warning' | 'critical'
export type SecurityScoreTier = 'low' | 'medium' | 'high'
export type SecurityPasswordHealth = 'unknown' | 'weak' | 'fair' | 'strong'
export type SecurityAlertChannel = 'email' | 'sms' | 'push' | 'in_app'
export type SecurityMfaFactorType = 'totp' | 'sms' | 'push' | 'hardware_key' | 'backup_codes'
export type SecuritySessionRisk = 'low' | 'medium' | 'high' | 'unknown'

export type SecurityRiskAlert = {
  id: string
  message: string
  severity: SecurityRiskSeverity
  createdAt: string
  acknowledgedAt?: string | null
}

export type SecurityOverview = {
  score: number
  tier: SecurityScoreTier
  summary: string
  lastPasswordChange?: string | null
  passwordHealth: SecurityPasswordHealth
  mfaEnabled: boolean
  trustedDevices: number
  untrustedDevices: number
  pendingAlerts: number
  lastAnomalyAt?: string | null
  riskAlerts: SecurityRiskAlert[]
}

export type SecurityPasswordPolicy = {
  minLength: number
  requireUppercase: boolean
  requireLowercase: boolean
  requireNumber: boolean
  requireSymbol: boolean
  expiryDays?: number | null
  historyCount: number
  minScore: number
}

export type SecurityPasswordHistoryEntry = {
  id: string
  changedAt: string
  location?: string | null
  client?: string | null
}

export type SecurityPasswordSettings = {
  policy: SecurityPasswordPolicy
  history: SecurityPasswordHistoryEntry[]
}

export type SecurityHardwareKey = {
  id: string
  label: string
  addedAt?: string | null
  lastUsedAt?: string | null
  transports?: string[]
}

export type SecurityAuthenticatorCatalogDetails = {
  id: string
  label: string
  description?: string | null
  helper?: string | null
  docsUrl?: string | null
  tags?: string[] | null
  issuer?: string | null
  metadata?: JsonValue | null
}

export type SecurityAuthenticatorFactorType = Uppercase<SecurityMfaFactorType>

export type SecurityAuthenticatorCatalogEntry = SecurityAuthenticatorCatalogDetails & {
  factorType: SecurityAuthenticatorFactorType
  sortOrder?: number | null
  isArchived?: boolean | null
}

export type SecurityMfaFactorStatus = 'pending' | 'active' | 'disabled' | 'revoked'

export type SecurityMfaFactor = {
  id: string
  type: SecurityMfaFactorType
  label: string
  enabled: boolean
  status: SecurityMfaFactorStatus
  enrolledAt?: string | null
  lastUsedAt?: string | null
  devices?: SecurityHardwareKey[]
  remainingCodes?: number | null
  metadata?: JsonValue
  catalogId?: string | null
}

export type SecurityPendingMfaEnrollment = {
  ticket: string
  factorId: string
  mode: 'create' | 'rotate'
  type: SecurityMfaFactorType
  label: string
  catalogId?: string | null
  expiresAt?: string | null
  status: SecurityMfaFactorStatus
  catalog?: SecurityAuthenticatorCatalogDetails | null
  description?: string | null
  helper?: string | null
  docsUrl?: string | null
  tags?: string[] | null
  issuer?: string | null
  metadata?: JsonValue | null
}

export type SecurityMfaRecommendation = {
  type: SecurityMfaFactorType
  reason: string
}

export type SecuritySession = {
  id: string
  device: string
  platform?: string | null
  browser?: string | null
  ipAddress?: string | null
  location?: string | null
  createdAt: string
  lastActiveAt: string
  trusted: boolean
  current: boolean
  risk: SecuritySessionRisk
}

export type SecuritySessionSummary = {
  activeCount: number
  trustedCount: number
  lastRotationAt?: string | null
  lastUntrustedAt?: string | null
}

export type SecurityRecoveryChannel = {
  type: 'email' | 'sms'
  value: string
  verified: boolean
  lastVerifiedAt?: string | null
}

export type SecurityBreakGlassContact = {
  id: string
  name: string
  email: string
  phone?: string | null
  verified: boolean
}

export type SecurityRecoverySettings = {
  primaryEmail: SecurityRecoveryChannel
  backupEmail?: SecurityRecoveryChannel
  sms?: SecurityRecoveryChannel
  backupCodesRemaining: number
  lastCodesGeneratedAt?: string | null
  contacts: SecurityBreakGlassContact[]
}

export type SecurityAlertPreference = {
  event: 'login' | 'new_device' | 'password_change' | 'mfa_disabled' | 'recovery_code' | string
  label: string
  enabled: boolean
  channels: SecurityAlertChannel[]
}

export type SecurityAlertSettings = {
  preferences: SecurityAlertPreference[]
  defaultChannels: SecurityAlertChannel[]
}

export type SecurityEventEntry = {
  id: string
  action: string
  description: string
  severity: SecurityRiskSeverity
  createdAt: string
  ipAddress?: string | null
  location?: string | null
  metadata?: JsonValue
}

export type SecurityMfaEnrollmentPrompt = {
  ticket: string
  factorId: string
  mode: 'create' | 'rotate'
  type: SecurityMfaFactorType
  label?: string
  secret?: string
  uri?: string
  qrCodeDataUrl?: string
  expiresAt?: string | null
  catalogId?: string | null
}

export type SecurityMfaEnrollmentResult = {
  factor: SecurityMfaFactor
  backupCodes?: string[]
}

export type AccountSecuritySnapshot = {
  overview: SecurityOverview
  password: SecurityPasswordSettings
  mfa: {
    factors: SecurityMfaFactor[]
    recommendations: SecurityMfaRecommendation[]
    pendingEnrollment?: SecurityPendingMfaEnrollment | null
  }
  sessions: {
    summary: SecuritySessionSummary
    list: SecuritySession[]
  }
  recovery: SecurityRecoverySettings
  alerts: SecurityAlertSettings
  events: SecurityEventEntry[]
}

const DEFAULT_OVERVIEW: SecurityOverview = {
  score: 65,
  tier: 'medium',
  summary: 'Review pending recommendations to reach High confidence.',
  lastPasswordChange: null,
  passwordHealth: 'unknown',
  mfaEnabled: false,
  trustedDevices: 0,
  untrustedDevices: 0,
  pendingAlerts: 0,
  lastAnomalyAt: null,
  riskAlerts: [],
}

const DEFAULT_PASSWORD_POLICY: SecurityPasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSymbol: true,
  expiryDays: 365,
  historyCount: 10,
  minScore: 4,
}

const DEFAULT_RECOVERY_CHANNEL: SecurityRecoveryChannel = {
  type: 'email',
  value: '',
  verified: false,
  lastVerifiedAt: null,
}

const DEFAULT_RECOVERY_SETTINGS: SecurityRecoverySettings = {
  primaryEmail: { ...DEFAULT_RECOVERY_CHANNEL },
  backupEmail: undefined,
  sms: undefined,
  backupCodesRemaining: 0,
  lastCodesGeneratedAt: null,
  contacts: [],
}

const DEFAULT_ALERT_SETTINGS: SecurityAlertSettings = {
  preferences: [
    { event: 'login', label: 'Successful login', enabled: true, channels: ['email'] },
    { event: 'new_device', label: 'New device detected', enabled: true, channels: ['email', 'push'] },
    { event: 'password_change', label: 'Password changed', enabled: true, channels: ['email'] },
    { event: 'mfa_disabled', label: 'MFA disabled', enabled: true, channels: ['email', 'sms'] },
  ],
  defaultChannels: ['email'],
}

const DEFAULT_SNAPSHOT: AccountSecuritySnapshot = {
  overview: DEFAULT_OVERVIEW,
  password: {
    policy: DEFAULT_PASSWORD_POLICY,
    history: [],
  },
  mfa: {
    factors: [],
    recommendations: [],
    pendingEnrollment: null,
  },
  sessions: {
    summary: { activeCount: 0, trustedCount: 0, lastRotationAt: null, lastUntrustedAt: null },
    list: [],
  },
  recovery: { ...DEFAULT_RECOVERY_SETTINGS },
  alerts: DEFAULT_ALERT_SETTINGS,
  events: [],
}

const coerceNumber = (value: unknown, fallback: number): number => {
  const num = Number(value)
  return Number.isFinite(num) ? num : fallback
}

const coerceBoolean = (value: unknown, fallback: boolean): boolean => {
  if (typeof value === 'boolean') return value
  if (value === 'true') return true
  if (value === 'false') return false
  return fallback
}

const coerceString = (value: unknown, fallback = ''): string => {
  if (typeof value === 'string') return value
  if (typeof value === 'number') return String(value)
  return fallback
}

const coerceDate = (value: unknown): string | null => {
  if (typeof value === 'string' && value.trim().length) return value
  if (value instanceof Date) return value.toISOString()
  return null
}

const coerceStringArray = (value: unknown, fallback: string[]): string[] => {
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

const AUTHENTICATOR_FACTOR_TYPES: SecurityAuthenticatorFactorType[] = ['TOTP', 'SMS', 'PUSH', 'HARDWARE_KEY', 'BACKUP_CODES']

const coerceAlertChannels = (value: unknown, fallback: SecurityAlertChannel[]): SecurityAlertChannel[] => {
  if (!Array.isArray(value)) return [...fallback]
  return value
    .map((entry) => (typeof entry === 'string' ? entry : null))
    .filter((entry): entry is string => Boolean(entry))
    .map((entry) => (entry === 'sms' || entry === 'push' || entry === 'in_app' ? entry : 'email')) as SecurityAlertChannel[]
}

const coerceFactorStatus = (value: unknown, fallback: SecurityMfaFactorStatus): SecurityMfaFactorStatus => {
  if (value === 'pending' || value === 'active' || value === 'disabled' || value === 'revoked') return value
  return fallback
}

const normalizeRecoveryChannel = (value: unknown, fallback: SecurityRecoveryChannel = DEFAULT_RECOVERY_CHANNEL): SecurityRecoveryChannel => {
  if (!value || typeof value !== 'object') return { ...fallback }
  const record = value as Record<string, unknown>
  const type = record.type === 'sms' ? 'sms' : 'email'
  return {
    type,
    value: coerceString(record.value, fallback.value),
    verified: coerceBoolean(record.verified, fallback.verified),
    lastVerifiedAt: coerceDate(record.lastVerifiedAt),
  }
}

const normalizeRecoverySettings = (value: unknown): SecurityRecoverySettings => {
  if (!value || typeof value !== 'object') return { ...DEFAULT_RECOVERY_SETTINGS, primaryEmail: { ...DEFAULT_RECOVERY_CHANNEL } }
  const record = value as Record<string, unknown>
  return {
    primaryEmail: normalizeRecoveryChannel(record.primaryEmail, DEFAULT_RECOVERY_CHANNEL),
    backupEmail: record.backupEmail ? normalizeRecoveryChannel(record.backupEmail) : undefined,
    sms: record.sms ? normalizeRecoveryChannel(record.sms, { ...DEFAULT_RECOVERY_CHANNEL, type: 'sms' }) : undefined,
    backupCodesRemaining: coerceNumber(record.backupCodesRemaining, DEFAULT_RECOVERY_SETTINGS.backupCodesRemaining),
    lastCodesGeneratedAt: coerceDate(record.lastCodesGeneratedAt),
    contacts: Array.isArray(record.contacts)
      ? record.contacts.map((entry, index) => normalizeBreakGlassContact(entry, index))
      : [],
  }
}

const normalizeBreakGlassContact = (value: unknown, index: number): SecurityBreakGlassContact => {
  if (!value || typeof value !== 'object') {
    return {
      id: `contact-${index}`,
      name: 'Backup contact',
      email: 'contact@example.com',
      phone: null,
      verified: false,
    }
  }
  const record = value as Record<string, unknown>
  return {
    id: coerceString(record.id, `contact-${index}`),
    name: coerceString(record.name, 'Backup contact'),
    email: coerceString(record.email, 'contact@example.com'),
    phone: record.phone ? coerceString(record.phone) : null,
    verified: coerceBoolean(record.verified, false),
  }
}

const normalizeRiskAlert = (value: unknown, index: number): SecurityRiskAlert => {
  if (!value || typeof value !== 'object') {
    return {
      id: `risk-${index}`,
      message: 'Unrecognized sign-in attempt detected',
      severity: 'warning',
      createdAt: new Date().toISOString(),
      acknowledgedAt: null,
    }
  }
  const record = value as Record<string, unknown>
  const severity = record.severity === 'critical' ? 'critical' : record.severity === 'info' ? 'info' : 'warning'
  return {
    id: coerceString(record.id, `risk-${index}`),
    message: coerceString(record.message, 'Review this security event'),
    severity,
    createdAt: coerceDate(record.createdAt) ?? new Date().toISOString(),
    acknowledgedAt: coerceDate(record.acknowledgedAt),
  }
}

const normalizeOverview = (value: unknown): SecurityOverview => {
  if (!value || typeof value !== 'object') return { ...DEFAULT_OVERVIEW }
  const record = value as Record<string, unknown>
  return {
    score: coerceNumber(record.score, DEFAULT_OVERVIEW.score),
    tier: record.tier === 'low' || record.tier === 'high' ? record.tier : 'medium',
    summary: coerceString(record.summary, DEFAULT_OVERVIEW.summary),
    lastPasswordChange: coerceDate(record.lastPasswordChange),
    passwordHealth: record.passwordHealth === 'weak' || record.passwordHealth === 'strong' ? record.passwordHealth : 'fair',
    mfaEnabled: coerceBoolean(record.mfaEnabled, DEFAULT_OVERVIEW.mfaEnabled),
    trustedDevices: coerceNumber(record.trustedDevices, DEFAULT_OVERVIEW.trustedDevices),
    untrustedDevices: coerceNumber(record.untrustedDevices, DEFAULT_OVERVIEW.untrustedDevices),
    pendingAlerts: coerceNumber(record.pendingAlerts, DEFAULT_OVERVIEW.pendingAlerts),
    lastAnomalyAt: coerceDate(record.lastAnomalyAt),
    riskAlerts: Array.isArray(record.riskAlerts) ? record.riskAlerts.map(normalizeRiskAlert) : [],
  }
}

const normalizePasswordSettings = (value: unknown): SecurityPasswordSettings => {
  if (!value || typeof value !== 'object') return { policy: { ...DEFAULT_PASSWORD_POLICY }, history: [] }
  const record = value as Record<string, unknown>
  const policyRaw = record.policy as Record<string, unknown> | undefined
  const historyRaw = Array.isArray(record.history) ? record.history : []
  const policy: SecurityPasswordPolicy = {
    minLength: coerceNumber(policyRaw?.minLength, DEFAULT_PASSWORD_POLICY.minLength),
    requireUppercase: coerceBoolean(policyRaw?.requireUppercase, DEFAULT_PASSWORD_POLICY.requireUppercase),
    requireLowercase: coerceBoolean(policyRaw?.requireLowercase, DEFAULT_PASSWORD_POLICY.requireLowercase),
    requireNumber: coerceBoolean(policyRaw?.requireNumber, DEFAULT_PASSWORD_POLICY.requireNumber),
    requireSymbol: coerceBoolean(policyRaw?.requireSymbol, DEFAULT_PASSWORD_POLICY.requireSymbol),
    expiryDays: policyRaw?.expiryDays === null ? null : coerceNumber(policyRaw?.expiryDays, DEFAULT_PASSWORD_POLICY.expiryDays ?? 0),
    historyCount: coerceNumber(policyRaw?.historyCount, DEFAULT_PASSWORD_POLICY.historyCount),
    minScore: coerceNumber(policyRaw?.minScore, DEFAULT_PASSWORD_POLICY.minScore),
  }
  const history: SecurityPasswordHistoryEntry[] = historyRaw.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      return {
        id: `password-${index}`,
        changedAt: new Date().toISOString(),
        location: null,
        client: null,
      }
    }
    const row = entry as Record<string, unknown>
    return {
      id: coerceString(row.id, `password-${index}`),
      changedAt: coerceDate(row.changedAt) ?? new Date().toISOString(),
      location: row.location ? coerceString(row.location) : null,
      client: row.client ? coerceString(row.client) : null,
    }
  })
  return { policy, history }
}

const normalizeHardwareKey = (value: unknown, index: number): SecurityHardwareKey => {
  if (!value || typeof value !== 'object') {
    return {
      id: `hw-${index}`,
      label: 'Security key',
      addedAt: null,
      lastUsedAt: null,
      transports: [],
    }
  }
  const record = value as Record<string, unknown>
  return {
    id: coerceString(record.id, `hw-${index}`),
    label: coerceString(record.label, 'Security key'),
    addedAt: coerceDate(record.addedAt),
    lastUsedAt: coerceDate(record.lastUsedAt),
    transports: coerceStringArray(record.transports, []),
  }
}

const normalizeMfaFactor = (value: unknown, index: number): SecurityMfaFactor => {
  if (!value || typeof value !== 'object') {
    return {
      id: `factor-${index}`,
      type: 'totp',
      label: 'Authenticator app',
      enabled: false,
      status: 'disabled',
      enrolledAt: null,
      lastUsedAt: null,
      devices: [],
      remainingCodes: null,
      metadata: null,
      catalogId: null,
    }
  }
  const record = value as Record<string, unknown>
  const type: SecurityMfaFactorType = record.type === 'sms' || record.type === 'push' || record.type === 'hardware_key' || record.type === 'backup_codes'
    ? record.type
    : 'totp'
  const devicesRaw = Array.isArray(record.devices) ? record.devices : []
  const enabled = coerceBoolean(record.enabled, true)
  return {
    id: coerceString(record.id, `factor-${index}`),
    type,
    label: coerceString(record.label, type === 'totp' ? 'Authenticator app' : type.toUpperCase()),
    enabled,
    status: coerceFactorStatus(record.status, enabled ? 'active' : 'disabled'),
    enrolledAt: coerceDate(record.enrolledAt),
    lastUsedAt: coerceDate(record.lastUsedAt),
    devices: devicesRaw.map((device, deviceIndex) => normalizeHardwareKey(device, deviceIndex)),
    remainingCodes: record.remainingCodes == null ? null : coerceNumber(record.remainingCodes, 0),
    metadata: (record.metadata as JsonValue) ?? null,
    catalogId: record.catalogId ? coerceString(record.catalogId) : null,
  }
}

const normalizeCatalogDetails = (value: unknown): SecurityAuthenticatorCatalogDetails | null => {
  if (!value || typeof value !== 'object') return null
  const record = value as Record<string, unknown>
  const id = coerceString(record.id)
  if (!id) return null
  const tags = record.tags != null ? coerceStringArray(record.tags, []) : []
  return {
    id,
    label: coerceString(record.label, 'Authenticator'),
    description: record.description ? coerceString(record.description) : null,
    helper: record.helper ? coerceString(record.helper) : null,
    docsUrl: record.docsUrl ? coerceString(record.docsUrl) : null,
    tags: tags.length ? tags : null,
    issuer: record.issuer ? coerceString(record.issuer) : null,
    metadata: (record.metadata as JsonValue) ?? null,
  }
}

export function normalizeSecurityAuthenticatorCatalogEntry(value: unknown): SecurityAuthenticatorCatalogEntry | null {
  const details = normalizeCatalogDetails(value)
  if (!details || !value || typeof value !== 'object') return null
  const record = value as Record<string, unknown>
  const rawFactor = typeof record.factorType === 'string' ? record.factorType.trim().toUpperCase() : ''
  if (!AUTHENTICATOR_FACTOR_TYPES.includes(rawFactor as SecurityAuthenticatorFactorType)) return null
  let sortOrder: number | null = null
  if (record.sortOrder != null && record.sortOrder !== '') {
    const numeric = Number(record.sortOrder)
    sortOrder = Number.isFinite(numeric) ? numeric : null
  }
  const archived = record.isArchived == null ? null : coerceBoolean(record.isArchived, false)
  return {
    ...details,
    factorType: rawFactor as SecurityAuthenticatorFactorType,
    sortOrder,
    isArchived: archived,
  }
}

const normalizePendingEnrollment = (value: unknown): SecurityPendingMfaEnrollment | null => {
  if (!value || typeof value !== 'object') return null
  const record = value as Record<string, unknown>
  const ticket = coerceString(record.ticket)
  const factorId = coerceString(record.factorId)
  if (!ticket || !factorId) return null
  const type: SecurityMfaFactorType = record.type === 'sms' || record.type === 'push' || record.type === 'hardware_key' || record.type === 'backup_codes'
    ? record.type
    : 'totp'
  const catalog = normalizeCatalogDetails(record.catalog)
  const explicitTags = record.tags != null ? coerceStringArray(record.tags, []) : []
  const normalizedTags = record.tags != null ? (explicitTags.length ? explicitTags : null) : null
  const helper = record.helper ? coerceString(record.helper) : catalog?.helper ?? null
  const docsUrl = record.docsUrl ? coerceString(record.docsUrl) : catalog?.docsUrl ?? null
  const description = record.description ? coerceString(record.description) : catalog?.description ?? null
  const issuer = record.issuer ? coerceString(record.issuer) : catalog?.issuer ?? null
  const metadata = catalog?.metadata ?? ((record.metadata as JsonValue) ?? null)
  return {
    ticket,
    factorId,
    mode: record.mode === 'rotate' ? 'rotate' : 'create',
    type,
    label: coerceString(record.label, type === 'totp' ? 'Authenticator app' : type.toUpperCase()),
    catalogId: record.catalogId ? coerceString(record.catalogId) : null,
    expiresAt: coerceDate(record.expiresAt),
    status: coerceFactorStatus(record.status, 'pending'),
    catalog,
    description,
    helper,
    docsUrl,
    tags: catalog?.tags ?? normalizedTags,
    issuer,
    metadata,
  }
}

const normalizeMfaRecommendations = (value: unknown): SecurityMfaRecommendation[] => {
  if (!Array.isArray(value)) return []
  return value.map((entry) => {
    if (!entry || typeof entry !== 'object') {
      return { type: 'hardware_key', reason: 'Add a hardware key for phishing-resistant MFA' }
    }
    const record = entry as Record<string, unknown>
    const type: SecurityMfaFactorType = record.type === 'sms' || record.type === 'push' || record.type === 'hardware_key' || record.type === 'backup_codes'
      ? record.type
      : 'totp'
    return {
      type,
      reason: coerceString(record.reason, 'Complete this MFA recommendation'),
    }
  })
}

const normalizeSession = (value: unknown, index: number): SecuritySession => {
  if (!value || typeof value !== 'object') {
    const now = new Date().toISOString()
    return {
      id: `session-${index}`,
      device: 'Unknown device',
      platform: null,
      browser: null,
      ipAddress: null,
      location: null,
      createdAt: now,
      lastActiveAt: now,
      trusted: false,
      current: false,
      risk: 'unknown',
    }
  }
  const record = value as Record<string, unknown>
  const risk: SecuritySessionRisk = record.risk === 'high' || record.risk === 'medium' || record.risk === 'low' ? record.risk : 'unknown'
  return {
    id: coerceString(record.id, `session-${index}`),
    device: coerceString(record.device, 'Device'),
    platform: record.platform ? coerceString(record.platform) : null,
    browser: record.browser ? coerceString(record.browser) : null,
    ipAddress: record.ipAddress ? coerceString(record.ipAddress) : null,
    location: record.location ? coerceString(record.location) : null,
    createdAt: coerceDate(record.createdAt) ?? new Date().toISOString(),
    lastActiveAt: coerceDate(record.lastActiveAt) ?? new Date().toISOString(),
    trusted: coerceBoolean(record.trusted, false),
    current: coerceBoolean(record.current, false),
    risk,
  }
}

const normalizeSessions = (value: unknown): { summary: SecuritySessionSummary; list: SecuritySession[] } => {
  if (!value || typeof value !== 'object') return { ...DEFAULT_SNAPSHOT.sessions }
  const record = value as Record<string, unknown>
  const summaryRaw = record.summary as Record<string, unknown> | undefined
  const listRaw = Array.isArray(record.list) ? record.list : []
  const summary: SecuritySessionSummary = {
    activeCount: coerceNumber(summaryRaw?.activeCount, 0),
    trustedCount: coerceNumber(summaryRaw?.trustedCount, 0),
    lastRotationAt: coerceDate(summaryRaw?.lastRotationAt),
    lastUntrustedAt: coerceDate(summaryRaw?.lastUntrustedAt),
  }
  const list = listRaw.map((entry, index) => normalizeSession(entry, index))
  return { summary, list }
}

const normalizeAlertPreference = (value: unknown, index: number): SecurityAlertPreference => {
  if (!value || typeof value !== 'object') {
    return { event: `custom-${index}`, label: 'Custom alert', enabled: true, channels: ['email'] }
  }
  const record = value as Record<string, unknown>
  const event = coerceString(record.event, `custom-${index}`)
  return {
    event,
    label: coerceString(record.label, event),
    enabled: coerceBoolean(record.enabled, true),
    channels: coerceAlertChannels(record.channels, ['email']),
  }
}

const normalizeAlerts = (value: unknown): SecurityAlertSettings => {
  if (!value || typeof value !== 'object') return { ...DEFAULT_ALERT_SETTINGS, preferences: [...DEFAULT_ALERT_SETTINGS.preferences] }
  const record = value as Record<string, unknown>
  return {
    preferences: Array.isArray(record.preferences)
      ? record.preferences.map((entry, index) => normalizeAlertPreference(entry, index))
      : [...DEFAULT_ALERT_SETTINGS.preferences],
    defaultChannels: coerceAlertChannels(record.defaultChannels, DEFAULT_ALERT_SETTINGS.defaultChannels),
  }
}

const normalizeEvents = (value: unknown): SecurityEventEntry[] => {
  if (!Array.isArray(value)) return []
  return value.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      return {
        id: `event-${index}`,
        action: 'auth.login',
        description: 'Login detected',
        severity: 'info' as SecurityRiskSeverity,
        createdAt: new Date().toISOString(),
        ipAddress: null,
        location: null,
        metadata: null,
      }
    }
    const record = entry as Record<string, unknown>
    const severity: SecurityRiskSeverity = record.severity === 'critical' || record.severity === 'warning' ? record.severity : 'info'
    return {
      id: coerceString(record.id, `event-${index}`),
      action: coerceString(record.action, 'auth.login'),
      description: coerceString(record.description, 'Security event logged'),
      severity,
      createdAt: coerceDate(record.createdAt) ?? new Date().toISOString(),
      ipAddress: record.ipAddress ? coerceString(record.ipAddress) : null,
      location: record.location ? coerceString(record.location) : null,
      metadata: (record.metadata as JsonValue) ?? null,
    }
  })
}

export function normalizeAccountSecuritySnapshot(value?: Record<string, unknown> | null): AccountSecuritySnapshot {
  if (!value || typeof value !== 'object') return { ...DEFAULT_SNAPSHOT, overview: { ...DEFAULT_OVERVIEW }, password: { policy: { ...DEFAULT_PASSWORD_POLICY }, history: [] }, recovery: { ...DEFAULT_RECOVERY_SETTINGS, primaryEmail: { ...DEFAULT_RECOVERY_CHANNEL } }, alerts: { ...DEFAULT_ALERT_SETTINGS, preferences: [...DEFAULT_ALERT_SETTINGS.preferences] } }
  const record = value as Record<string, unknown>
  const mfaRecord = record.mfa && typeof record.mfa === 'object' ? (record.mfa as Record<string, unknown>) : undefined
  const mfaFactors = Array.isArray(mfaRecord?.factors) ? (mfaRecord!.factors as unknown[]) : []
  return {
    overview: normalizeOverview(record.overview),
    password: normalizePasswordSettings(record.password),
    mfa: {
      factors: mfaFactors.map((entry, index) => normalizeMfaFactor(entry, index)),
      recommendations: normalizeMfaRecommendations(mfaRecord?.recommendations),
      pendingEnrollment: normalizePendingEnrollment(mfaRecord?.pendingEnrollment)
    },
    sessions: normalizeSessions(record.sessions),
    recovery: normalizeRecoverySettings(record.recovery),
    alerts: normalizeAlerts(record.alerts),
    events: normalizeEvents(record.events),
  }
}

export const DEFAULT_SECURITY_SNAPSHOT = DEFAULT_SNAPSHOT
