import { PrismaClient, Prisma } from '@prisma/client';
import type { RefreshToken, PasswordHistory, Setting, AuditLog, User, UserDevice, UserMfaFactor, UserBackupCode } from '@prisma/client';
import argon2 from 'argon2';
import { createHash, randomBytes } from 'crypto';
import { meetsRegistrationPasswordRequirements } from '../lib/passwordPolicy';
import { buildTotpQrCode, buildTotpUri, generateTotpSecret, verifyTotpCode } from '../lib/totp';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type SecurityPrisma = {
  user: PrismaClient['user'];
  passwordHistory: PrismaClient['passwordHistory'];
  refreshToken: PrismaClient['refreshToken'];
  auditLog: PrismaClient['auditLog'];
  setting: PrismaClient['setting'];
  userDevice: PrismaClient['userDevice'];
  userMfaFactor: PrismaClient['userMfaFactor'];
  userBackupCode: PrismaClient['userBackupCode'];
  $transaction: PrismaClient['$transaction'];
};

export type SecurityRiskSeverity = 'info' | 'warning' | 'critical';
export type SecurityScoreTier = 'low' | 'medium' | 'high';
export type SecurityPasswordHealth = 'unknown' | 'weak' | 'fair' | 'strong';
export type SecurityAlertChannel = 'email' | 'sms' | 'push' | 'in_app';
export type SecurityMfaFactorType = 'totp' | 'sms' | 'push' | 'hardware_key' | 'backup_codes';
export type SecuritySessionRisk = 'low' | 'medium' | 'high' | 'unknown';

export type SecurityRiskAlert = {
  id: string;
  message: string;
  severity: SecurityRiskSeverity;
  createdAt: string;
  acknowledgedAt?: string | null;
};

export type SecurityOverview = {
  score: number;
  tier: SecurityScoreTier;
  summary: string;
  lastPasswordChange?: string | null;
  passwordHealth: SecurityPasswordHealth;
  mfaEnabled: boolean;
  trustedDevices: number;
  untrustedDevices: number;
  pendingAlerts: number;
  lastAnomalyAt?: string | null;
  riskAlerts: SecurityRiskAlert[];
};

export type SecurityPasswordPolicy = {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumber: boolean;
  requireSymbol: boolean;
  expiryDays?: number | null;
  historyCount: number;
  minScore: number;
};

export type SecurityPasswordHistoryEntry = {
  id: string;
  changedAt: string;
  location?: string | null;
  client?: string | null;
};

export type SecurityPasswordSettings = {
  policy: SecurityPasswordPolicy;
  history: SecurityPasswordHistoryEntry[];
};

export type SecurityHardwareKey = {
  id: string;
  label: string;
  addedAt?: string | null;
  lastUsedAt?: string | null;
  transports?: string[];
};

export type SecurityMfaFactorStatus = 'pending' | 'active' | 'disabled' | 'revoked';

export type SecurityMfaFactor = {
  id: string;
  type: SecurityMfaFactorType;
  label: string;
  enabled: boolean;
  status: SecurityMfaFactorStatus;
  enrolledAt?: string | null;
  lastUsedAt?: string | null;
  devices?: SecurityHardwareKey[];
  remainingCodes?: number | null;
  metadata?: JsonValue | null;
};

export type SecurityMfaRecommendation = {
  type: SecurityMfaFactorType;
  reason: string;
};

export type SecuritySession = {
  id: string;
  device: string;
  platform?: string | null;
  browser?: string | null;
  ipAddress?: string | null;
  location?: string | null;
  createdAt: string;
  lastActiveAt: string;
  trusted: boolean;
  current: boolean;
  risk: SecuritySessionRisk;
};

export type SecuritySessionSummary = {
  activeCount: number;
  trustedCount: number;
  lastRotationAt?: string | null;
  lastUntrustedAt?: string | null;
};

export type SecurityRecoveryChannel = {
  type: 'email' | 'sms';
  value: string;
  verified: boolean;
  lastVerifiedAt?: string | null;
};

export type SecurityBreakGlassContact = {
  id: string;
  name: string;
  email: string;
  phone?: string | null;
  verified: boolean;
};

export type SecurityRecoverySettings = {
  primaryEmail: SecurityRecoveryChannel;
  backupEmail?: SecurityRecoveryChannel;
  sms?: SecurityRecoveryChannel;
  backupCodesRemaining: number;
  lastCodesGeneratedAt?: string | null;
  contacts: SecurityBreakGlassContact[];
};

type SecurityRecoveryChannelInput = Omit<SecurityRecoveryChannel, 'verified'> & { verified?: boolean };
type SecurityBreakGlassContactInput = {
  id?: string;
  name: string;
  email: string;
  phone?: string | null;
  verified?: boolean;
};

export type SecurityRecoverySettingsInput = {
  primaryEmail: SecurityRecoveryChannelInput;
  backupEmail?: SecurityRecoveryChannelInput | null;
  sms?: SecurityRecoveryChannelInput | null;
  backupCodesRemaining?: number;
  lastCodesGeneratedAt?: string | null;
  contacts?: SecurityBreakGlassContactInput[];
};

export type SecurityAlertPreference = {
  event: string;
  label: string;
  enabled: boolean;
  channels: SecurityAlertChannel[];
};

export type SecurityAlertSettings = {
  preferences: SecurityAlertPreference[];
  defaultChannels: SecurityAlertChannel[];
};

export type SecurityAlertPreferenceInput = {
  event: string;
  label?: string | null;
  enabled?: boolean | null;
  channels?: SecurityAlertChannel[] | null;
};

export type SecurityAlertSettingsInput = {
  preferences?: SecurityAlertPreferenceInput[] | null;
  defaultChannels?: SecurityAlertChannel[] | null;
};

export type SecurityPasswordChangeInput = {
  currentPassword: string;
  newPassword: string;
  signOutOthers?: boolean;
};

export type PasswordChangeContext = {
  currentRefreshToken?: string | null;
  requestMeta?: {
    ipAddress?: string | null;
    userAgent?: string | null;
  };
};

export type SecurityEventEntry = {
  id: string;
  action: string;
  description: string;
  severity: SecurityRiskSeverity;
  createdAt: string;
  ipAddress?: string | null;
  location?: string | null;
  metadata?: JsonValue;
};

export type SecurityTotpEnrollmentPrompt = {
  ticket: string;
  type: SecurityMfaFactorType;
  factorId: string;
  mode: 'create' | 'rotate';
  secret: string;
  uri: string;
  qrCodeDataUrl?: string;
  expiresAt?: string | null;
};

export type SecurityTotpEnrollmentResult = {
  factor: SecurityMfaFactor;
  backupCodes: string[];
  expiresAt?: string | null;
};

export type AccountSecuritySnapshot = {
  overview: SecurityOverview;
  password: SecurityPasswordSettings;
  mfa: {
    factors: SecurityMfaFactor[];
    recommendations: SecurityMfaRecommendation[];
  };
  sessions: {
    summary: SecuritySessionSummary;
    list: SecuritySession[];
  };
  recovery: SecurityRecoverySettings;
  alerts: SecurityAlertSettings;
  events: SecurityEventEntry[];
};

export type SecuritySessionsPayload = {
  summary: SecuritySessionSummary;
  list: SecuritySession[];
};

type RefreshTokenWithDevice = RefreshToken & { device?: UserDevice | null };

export class PasswordChangeError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'PasswordChangeError';
    this.status = status;
  }
}

export class SecurityOperationError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'SecurityOperationError';
    this.status = status;
  }
}

const SECURITY_SETTING_KEYS = [
  'passwordMinLength',
  'passwordRequireUppercase',
  'passwordRequireLowercase',
  'passwordRequireNumber',
  'passwordRequireSymbol',
  'passwordExpiryDays',
  'passwordHistoryLimit',
  'passwordMinScore',
];

const DEFAULT_PASSWORD_POLICY: SecurityPasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber: true,
  requireSymbol: true,
  expiryDays: 365,
  historyCount: 10,
  minScore: 4,
};

const DEFAULT_ALERT_PREFERENCES: SecurityAlertPreference[] = [
  { event: 'login', label: 'Successful login', enabled: true, channels: ['email'] },
  { event: 'new_device', label: 'New device detected', enabled: true, channels: ['email', 'push'] },
  { event: 'password_change', label: 'Password changed', enabled: true, channels: ['email'] },
  { event: 'mfa_disabled', label: 'MFA disabled', enabled: true, channels: ['email', 'sms'] },
];

const DEFAULT_RECOVERY_CHANNEL: SecurityRecoveryChannel = {
  type: 'email',
  value: '',
  verified: false,
  lastVerifiedAt: null,
};

const DEFAULT_RECOVERY_SETTINGS: SecurityRecoverySettings = {
  primaryEmail: { ...DEFAULT_RECOVERY_CHANNEL },
  backupCodesRemaining: 0,
  lastCodesGeneratedAt: null,
  contacts: [],
};

const DEFAULT_RECOMMENDATIONS: SecurityMfaRecommendation[] = [
  { type: 'hardware_key', reason: 'Add a hardware security key for phishing-resistant MFA.' },
];

const DEFAULT_TOTP_LABEL = 'Authenticator app';

const MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;
const BACKUP_CODE_GROUP_LENGTH = 5;
const BACKUP_CODE_COUNT = 8;
const BACKUP_CODE_TTL_DAYS = 365;
const TOTP_ENROLLMENT_TTL_MIN = 15;
const ERROR_USER_NOT_FOUND = 'user not found';
const ERROR_FACTOR_NOT_FOUND = 'factor not found';
const ERROR_FACTOR_REVOKED = 'factor revoked';

type PendingTotpEnrollment = {
  ticket: string;
  factorId: string;
  mode: 'create' | 'rotate';
  expiresAt?: string | null;
};

export class SecurityService {
  private prisma: SecurityPrisma;

  constructor(opts?: { prisma?: SecurityPrisma }) {
    this.prisma = (opts?.prisma ?? new PrismaClient()) as SecurityPrisma;
  }

  async getAccountSecuritySnapshot(userId: string): Promise<AccountSecuritySnapshot | null> {
    const [user, passwordHistory, auditLogs, settingsRows, refreshTokens, devices, mfaFactors, backupCodes] = await Promise.all([
      this.prisma.user.findUnique({ where: { id: userId } }),
      this.prisma.passwordHistory.findMany({ where: { userId }, orderBy: { createdAt: 'desc' }, take: 15 }),
      this.prisma.auditLog.findMany({ where: { userId }, orderBy: { createdAt: 'desc' }, take: 20 }),
      this.prisma.setting.findMany({ where: { category: 'security', key: { in: SECURITY_SETTING_KEYS } } }),
      this.prisma.refreshToken.findMany({ where: { userId, revokedAt: null }, orderBy: { createdAt: 'desc' }, take: 25, include: { device: true } }),
      this.prisma.userDevice.findMany({ where: { userId }, orderBy: { updatedAt: 'desc' }, take: 50 }),
      this.prisma.userMfaFactor.findMany({ where: { userId }, orderBy: { createdAt: 'asc' } }),
      this.prisma.userBackupCode.findMany({ where: { userId } }),
    ]);

    if (!user) return null;

    const sessions = this.buildSessionResponse(refreshTokens, devices);
    const policy = this.buildPasswordPolicy(settingsRows);
    const history = this.buildPasswordHistory(passwordHistory);
    const riskAlerts = this.buildRiskAlerts(auditLogs);
    const metadata = this.extractSecurityMetadata(user);
    const mfa = this.buildMfaSnapshot(metadata.mfa, mfaFactors, backupCodes);
    const recovery = this.mergeRecoveryWithBackupCodes(this.normalizeRecoverySettings(metadata.recovery, user), backupCodes);
    const alerts = this.normalizeAlertSettings(metadata.alerts);
    const overview = this.buildOverview(user, sessions, history, riskAlerts, mfa.factors, devices);

    return {
      overview,
      password: { policy, history },
      mfa,
      sessions,
      recovery,
      alerts,
      events: this.buildSecurityEvents(auditLogs),
    };
  }

  async listSessions(userId: string): Promise<SecuritySessionsPayload> {
    const [tokens, devices] = await Promise.all([
      this.prisma.refreshToken.findMany({ where: { userId, revokedAt: null }, orderBy: { createdAt: 'desc' }, take: 25, include: { device: true } }),
      this.prisma.userDevice.findMany({ where: { userId }, orderBy: { updatedAt: 'desc' }, take: 50 }),
    ]);
    return this.buildSessionResponse(tokens, devices);
  }

  async revokeSession(userId: string, sessionId: string): Promise<void> {
    const token = await this.prisma.refreshToken.findFirst({ where: { id: sessionId, userId, revokedAt: null } });
    if (!token) {
      throw new SecurityOperationError(404, 'session not found');
    }
    await this.prisma.refreshToken.update({ where: { id: token.id }, data: { revokedAt: new Date() } }).catch(() => {});
  }

  async revokeAllSessions(userId: string, currentToken?: string | null): Promise<void> {
    await this.revokeOtherRefreshTokens(userId, currentToken ?? null);
  }

  async setSessionTrust(userId: string, sessionId: string, trust: boolean, meta?: { ipAddress?: string | null; userAgent?: string | null }): Promise<void> {
    const token = await this.prisma.refreshToken.findFirst({ where: { id: sessionId, userId, revokedAt: null }, include: { device: true } });
    if (!token) {
      throw new SecurityOperationError(404, 'session not found');
    }

    const now = new Date();
    const parsedAgent = this.parseUserAgent(token.userAgent ?? meta?.userAgent ?? '');
    const baseData: Prisma.UserDeviceUncheckedCreateInput = {
      userId,
      label: parsedAgent.device,
      platform: parsedAgent.platform,
      userAgent: token.userAgent ?? meta?.userAgent ?? null,
      ipAddress: token.ipAddress ?? meta?.ipAddress ?? null,
      lastSeenAt: now,
      trustedAt: trust ? now : null,
      trustSource: trust ? 'user' : null,
      status: trust ? 'active' : 'untrusted',
    };

    if (token.device) {
      await this.prisma.userDevice.update({
        where: { id: token.device.id },
        data: {
          trustedAt: trust ? now : null,
          trustSource: trust ? 'user' : token.device.trustSource,
          status: trust ? 'active' : 'untrusted',
          ipAddress: meta?.ipAddress ?? token.device.ipAddress,
          userAgent: meta?.userAgent ?? token.device.userAgent,
          lastSeenAt: now,
        },
      }).catch(() => {});
    } else if (token.deviceId) {
      await this.prisma.userDevice.update({
        where: { id: token.deviceId },
        data: {
          trustedAt: trust ? now : null,
          trustSource: trust ? 'user' : undefined,
          status: trust ? 'active' : 'untrusted',
          ipAddress: meta?.ipAddress ?? undefined,
          userAgent: meta?.userAgent ?? undefined,
          lastSeenAt: now,
        },
      }).catch(async () => {
        const created = await this.prisma.userDevice.create({ data: baseData });
        await this.prisma.refreshToken.update({ where: { id: token.id }, data: { deviceId: created.id } });
      });
    } else {
      const created = await this.prisma.userDevice.create({ data: baseData });
      await this.prisma.refreshToken.update({ where: { id: token.id }, data: { deviceId: created.id } }).catch(() => {});
    }
  }

  async startTotpEnrollment(userId: string, input?: { label?: string; issuer?: string; accountName?: string }): Promise<SecurityTotpEnrollmentPrompt> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new SecurityOperationError(404, ERROR_USER_NOT_FOUND);

    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const security = this.asRecord(metadata.security) ?? {};
    const pending = this.readPendingTotp(security);
    if (pending) {
      await this.discardPendingTotp(userId, pending);
      delete security.pendingTotp;
    }

    const secret = generateTotpSecret();
    const accountName = input?.accountName ?? user.email ?? 'Account';
    const issuer = input?.issuer ?? null;
    const label = await this.chooseTotpLabel(userId, input?.label);
    const duplicateLabel = this.normalizeFactorLabel(input?.label)
      ? await this.findTotpFactorByLabel(userId, label)
      : null;
    if (duplicateLabel) {
      return this.regenerateTotpFactor(userId, duplicateLabel.id, { ...input, label });
    }
    const ticket = randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + TOTP_ENROLLMENT_TTL_MIN * 60 * 1000);

    const factor = await this.prisma.userMfaFactor.create({
      data: {
        userId,
        type: 'TOTP',
        label,
        secret,
        enabled: false,
        status: 'PENDING',
        metadata: {
          enrollment: {
            ticket,
            expiresAt: expiresAt.toISOString(),
            issuer,
            accountName,
          },
        } as Prisma.InputJsonValue,
      },
    });

    const pendingEntry: PendingTotpEnrollment = {
      ticket,
      factorId: factor.id,
      mode: 'create',
      expiresAt: expiresAt.toISOString(),
    };
    security.pendingTotp = pendingEntry;
    const nextMetadata = { ...metadata, security } as Prisma.JsonObject;
    await this.prisma.user.update({ where: { id: userId }, data: { metadata: nextMetadata } as Prisma.UserUpdateInput });

    const uri = buildTotpUri(secret, { issuer: issuer ?? undefined, accountName });
    const qrCodeDataUrl = await buildTotpQrCode(uri);

    return {
      ticket,
      factorId: factor.id,
      mode: 'create',
      type: 'totp',
      secret,
      uri,
      qrCodeDataUrl,
      expiresAt: expiresAt.toISOString(),
    } satisfies SecurityTotpEnrollmentPrompt;
  }

  async confirmTotpEnrollment(userId: string, payload: { ticket: string; code: string }): Promise<SecurityTotpEnrollmentResult> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) throw new SecurityOperationError(404, ERROR_USER_NOT_FOUND);

    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const security = this.asRecord(metadata.security) ?? {};
    const pending = this.readPendingTotp(security);
    if (!pending) throw new SecurityOperationError(400, 'no pending enrollment');
    if (pending.ticket !== payload.ticket) {
      throw new SecurityOperationError(400, 'invalid enrollment ticket');
    }
    const expiresAt = pending.expiresAt ? new Date(String(pending.expiresAt)) : null;
    if (expiresAt && expiresAt.getTime() < Date.now()) {
      await this.discardPendingTotp(userId, pending);
      delete security.pendingTotp;
      const expiredMetadata = { ...metadata, security } as Prisma.JsonObject;
      await this.prisma.user.update({ where: { id: userId }, data: { metadata: expiredMetadata } as Prisma.UserUpdateInput }).catch(() => {});
      throw new SecurityOperationError(400, 'enrollment expired');
    }

    const factor = await this.prisma.userMfaFactor.findFirst({ where: { id: pending.factorId, userId } });
    if (!factor) {
      delete security.pendingTotp;
      const nextMetadata = { ...metadata, security } as Prisma.JsonObject;
      await this.prisma.user.update({ where: { id: userId }, data: { metadata: nextMetadata } as Prisma.UserUpdateInput }).catch(() => {});
  throw new SecurityOperationError(404, ERROR_FACTOR_NOT_FOUND);
    }

    const factorMetadata = this.cloneMetadata((factor as unknown as { metadata?: Prisma.JsonValue | null }).metadata ?? null);
    const enrollment = this.asRecord(factorMetadata.enrollment) ?? null;
    const secret = pending.mode === 'rotate'
      ? this.coerceString(enrollment?.pendingSecret)
      : this.coerceString(factor.secret);
    if (!secret) throw new SecurityOperationError(400, 'secret missing');
    if (!verifyTotpCode(secret, payload.code)) {
      throw new SecurityOperationError(400, 'invalid verification code');
    }

    const cleanedMetadata = this.prepareMetadataPayload(this.stripEnrollmentMetadata(factorMetadata));
    const updateData: Prisma.UserMfaFactorUpdateInput = {
      secret,
      enabled: true,
      status: 'ACTIVE',
      metadata: cleanedMetadata,
      enrolledAt: pending.mode === 'create' ? new Date() : factor.enrolledAt ?? new Date(),
    };
    await this.prisma.userMfaFactor.update({ where: { id: factor.id }, data: updateData });

    const codeBundle = this.generateBackupCodes();
    await this.prisma.$transaction([
      this.prisma.userBackupCode.deleteMany({ where: { userId } }),
      this.prisma.userBackupCode.createMany({
        data: codeBundle.hashed.map(entry => ({ userId, factorId: factor.id, codeHash: entry.hash })),
      }),
    ]).catch(() => {});

    delete security.pendingTotp;
    const nextMetadata = { ...metadata, security } as Prisma.JsonObject;
    await this.prisma.user.update({ where: { id: userId }, data: { metadata: nextMetadata } as Prisma.UserUpdateInput }).catch(() => {});

    const refreshedFactor = await this.prisma.userMfaFactor.findUnique({ where: { id: factor.id } }) ?? factor;

    return {
      factor: this.mapDbFactorToSnapshot(refreshedFactor, codeBundle.codes.length),
      backupCodes: codeBundle.codes,
      expiresAt: new Date(Date.now() + BACKUP_CODE_TTL_DAYS * MILLISECONDS_PER_DAY).toISOString(),
    } satisfies SecurityTotpEnrollmentResult;
  }

  async regenerateTotpFactor(userId: string, factorId: string, input?: { label?: string; issuer?: string; accountName?: string }): Promise<SecurityTotpEnrollmentPrompt> {
    const [user, factor] = await Promise.all([
      this.prisma.user.findUnique({ where: { id: userId } }),
      this.prisma.userMfaFactor.findFirst({ where: { id: factorId, userId } }),
    ]);
    if (!user) throw new SecurityOperationError(404, ERROR_USER_NOT_FOUND);
    if (!factor || factor.type !== 'TOTP') {
      throw new SecurityOperationError(404, ERROR_FACTOR_NOT_FOUND);
    }

    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const security = this.asRecord(metadata.security) ?? {};
    const pending = this.readPendingTotp(security);
    if (pending) {
      await this.discardPendingTotp(userId, pending);
      delete security.pendingTotp;
    }

    const secret = generateTotpSecret();
    const accountName = this.normalizeFactorLabel(input?.accountName) ?? user.email ?? 'Account';
    const issuer = this.normalizeFactorLabel(input?.issuer) ?? null;
    const label = this.normalizeFactorLabel(input?.label) ?? factor.label ?? DEFAULT_TOTP_LABEL;
    const ticket = randomBytes(24).toString('hex');
    const expiresAt = new Date(Date.now() + TOTP_ENROLLMENT_TTL_MIN * 60 * 1000);

    const factorMetadata = this.cloneMetadata((factor as unknown as { metadata?: Prisma.JsonValue | null }).metadata ?? null);
    factorMetadata.enrollment = {
      ticket,
      expiresAt: expiresAt.toISOString(),
      issuer,
      accountName,
      pendingSecret: secret,
      rotating: true,
    };

    await this.prisma.userMfaFactor.update({
      where: { id: factor.id },
      data: {
        label,
        metadata: this.prepareMetadataPayload(factorMetadata),
      },
    });

    const pendingEntry: PendingTotpEnrollment = {
      ticket,
      factorId: factor.id,
      mode: 'rotate',
      expiresAt: expiresAt.toISOString(),
    };
    security.pendingTotp = pendingEntry;
    const nextMetadata = { ...metadata, security } as Prisma.JsonObject;
    await this.prisma.user.update({ where: { id: userId }, data: { metadata: nextMetadata } as Prisma.UserUpdateInput });

    const uri = buildTotpUri(secret, { issuer: issuer ?? undefined, accountName });
    const qrCodeDataUrl = await buildTotpQrCode(uri);

    return {
      ticket,
      factorId: factor.id,
      mode: 'rotate',
      type: 'totp',
      secret,
      uri,
      qrCodeDataUrl,
      expiresAt: expiresAt.toISOString(),
    } satisfies SecurityTotpEnrollmentPrompt;
  }

  async disableMfaFactor(userId: string, factorId: string): Promise<void> {
    const factor = await this.prisma.userMfaFactor.findFirst({ where: { id: factorId, userId } });
    if (!factor) throw new SecurityOperationError(404, ERROR_FACTOR_NOT_FOUND);
    const metadata = this.cloneMetadata((factor as unknown as { metadata?: Prisma.JsonValue | null }).metadata ?? null);
    const cleanedMetadata = this.prepareMetadataPayload(this.stripEnrollmentMetadata(metadata));
    await this.prisma.userMfaFactor.update({ where: { id: factorId }, data: { enabled: false, status: 'DISABLED', metadata: cleanedMetadata } });
    if (factor.type === 'TOTP') {
      await this.prisma.userBackupCode.deleteMany({ where: { userId, factorId } });
    }
  }

  async enableMfaFactor(userId: string, factorId: string): Promise<void> {
    const factor = await this.prisma.userMfaFactor.findFirst({ where: { id: factorId, userId } });
    if (!factor) throw new SecurityOperationError(404, ERROR_FACTOR_NOT_FOUND);
    if (factor.status === 'REVOKED') {
      throw new SecurityOperationError(400, ERROR_FACTOR_REVOKED);
    }
    const metadata = this.cloneMetadata((factor as unknown as { metadata?: Prisma.JsonValue | null }).metadata ?? null);
    const cleanedMetadata = this.prepareMetadataPayload(this.stripEnrollmentMetadata(metadata));
    await this.prisma.userMfaFactor.update({
      where: { id: factorId },
      data: { enabled: true, status: 'ACTIVE', metadata: cleanedMetadata },
    });
  }

  async deleteMfaFactor(userId: string, factorId: string): Promise<void> {
    const factor = await this.prisma.userMfaFactor.findFirst({ where: { id: factorId, userId } });
    if (!factor) throw new SecurityOperationError(404, ERROR_FACTOR_NOT_FOUND);

    await this.prisma.userBackupCode.deleteMany({ where: { userId, factorId } }).catch(() => {});
    await this.prisma.userMfaFactor.delete({ where: { id: factor.id } });

    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return;
    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const security = this.asRecord(metadata.security) ?? {};
    const pending = this.readPendingTotp(security);
    if (pending?.factorId === factorId) {
      delete security.pendingTotp;
      const nextMetadata = { ...metadata, security } as Prisma.JsonObject;
      await this.prisma.user.update({ where: { id: userId }, data: { metadata: nextMetadata } as Prisma.UserUpdateInput }).catch(() => {});
    }
  }

  async regenerateBackupCodes(userId: string, factorId?: string): Promise<{ codes: string[]; expiresAt: string | null }> {
    const factor = factorId
      ? await this.prisma.userMfaFactor.findFirst({ where: { userId, id: factorId, enabled: true } })
      : await this.prisma.userMfaFactor.findFirst({ where: { userId, type: 'TOTP', enabled: true } });
    if (!factor) throw new SecurityOperationError(400, 'no active factors');
    const codeBundle = this.generateBackupCodes();
    await this.prisma.$transaction([
      this.prisma.userBackupCode.deleteMany({ where: { userId } }),
      this.prisma.userBackupCode.createMany({ data: codeBundle.hashed.map(entry => ({ userId, factorId: factor.id, codeHash: entry.hash })) }),
    ]);
    const expiresAt = new Date(Date.now() + BACKUP_CODE_TTL_DAYS * MILLISECONDS_PER_DAY).toISOString();
    return { codes: codeBundle.codes, expiresAt };
  }

  async updateRecoverySettings(userId: string, payload: SecurityRecoverySettingsInput): Promise<SecurityRecoverySettings | null> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return null;

    const existingRecovery = this.normalizeRecoverySettings(this.extractSecurityMetadata(user).recovery, user);
    const merged = this.mergeRecoverySettings(existingRecovery, payload);
    const normalized = this.normalizeRecoverySettings(merged, user);

    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const security = this.asRecord(metadata.security) ?? {};
    security.recovery = normalized;
    const nextMetadata = { ...metadata, security } as Prisma.JsonObject;

    await this.prisma.user.update({
      where: { id: userId },
      data: { metadata: nextMetadata } as Prisma.UserUpdateInput,
    });

    return normalized;
  }

  async updateAlertSettings(userId: string, payload: SecurityAlertSettingsInput): Promise<SecurityAlertSettings | null> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) return null;

    const existingAlerts = this.normalizeAlertSettings(this.extractSecurityMetadata(user).alerts);
    const merged = this.mergeAlertSettings(existingAlerts, payload);
    const normalized = this.normalizeAlertSettings(merged);

    const metadata = this.cloneMetadata((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata);
    const security = this.asRecord(metadata.security) ?? {};
    security.alerts = normalized;
    const nextMetadata = { ...metadata, security } as Prisma.JsonObject;

    await this.prisma.user.update({
      where: { id: userId },
      data: { metadata: nextMetadata } as Prisma.UserUpdateInput,
    });

    return normalized;
  }

  async changePassword(userId: string, input: SecurityPasswordChangeInput, ctx?: PasswordChangeContext): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.passwordHash) {
      throw new PasswordChangeError(404, 'user not found or password login disabled');
    }

    const currentMatches = await argon2.verify(String(user.passwordHash), input.currentPassword).catch(() => false);
    if (!currentMatches) {
      throw new PasswordChangeError(400, 'current password is incorrect');
    }

    if (!meetsRegistrationPasswordRequirements(input.newPassword)) {
      throw new PasswordChangeError(400, 'password does not meet complexity requirements');
    }

    const settingsRows = await this.prisma.setting.findMany({ where: { category: 'security', key: { in: SECURITY_SETTING_KEYS } } });
    const policy = this.buildPasswordPolicy(settingsRows);
    const historyLimit = Math.max(policy.historyCount ?? 0, 0);

    if (historyLimit > 0) {
      const recentHistory = await this.prisma.passwordHistory.findMany({ where: { userId }, orderBy: { createdAt: 'desc' }, take: historyLimit });
      for (const entry of recentHistory) {
        const reused = await argon2.verify(String(entry.passwordHash), input.newPassword).catch(() => false);
        if (reused) {
          throw new PasswordChangeError(400, 'new password must not match your recent passwords');
        }
      }
    }

    const matchesExisting = await argon2.verify(String(user.passwordHash), input.newPassword).catch(() => false);
    if (matchesExisting) {
      throw new PasswordChangeError(400, 'new password must not match your current password');
    }

    const hashOpts = process.env.NODE_ENV === 'test'
      ? { type: argon2.argon2id, timeCost: 2, memoryCost: 1024, parallelism: 1 }
      : { type: argon2.argon2id };
    const newHash = await argon2.hash(input.newPassword, hashOpts);

    await this.prisma.user.update({ where: { id: userId }, data: { passwordHash: newHash } });

    if (user.passwordHash) {
      await this.prisma.passwordHistory.create({ data: { userId, passwordHash: user.passwordHash } }).catch(() => {});
      if (historyLimit > 0) {
        const extra = await this.prisma.passwordHistory.findMany({ where: { userId }, orderBy: { createdAt: 'desc' }, skip: historyLimit, take: 100 });
        if (extra.length) {
          await this.prisma.passwordHistory.deleteMany({ where: { id: { in: extra.map(entry => entry.id) } } }).catch(() => {});
        }
      }
    }

    if (input.signOutOthers) {
      await this.revokeOtherRefreshTokens(userId, ctx?.currentRefreshToken ?? null);
    }

    if (ctx?.requestMeta) {
      await this.prisma.auditLog.create({
        data: {
          userId,
          action: 'auth.password_change',
          ipAddress: ctx.requestMeta.ipAddress ?? null,
          userAgent: ctx.requestMeta.userAgent ?? null,
          metadata: { signOutOthers: Boolean(input.signOutOthers) } as Prisma.InputJsonValue,
        },
      }).catch(() => {});
    }
  }

  private buildPasswordPolicy(settingsRows: Setting[]): SecurityPasswordPolicy {
    const map = new Map(settingsRows.map(row => [row.key, row.value]));
    const expiryRaw = map.get('passwordExpiryDays');
    const expiryDays = expiryRaw === null ? null : this.coerceNumber(expiryRaw, DEFAULT_PASSWORD_POLICY.expiryDays ?? 0);
    return {
      minLength: this.coerceNumber(map.get('passwordMinLength'), DEFAULT_PASSWORD_POLICY.minLength),
      requireUppercase: this.coerceBoolean(map.get('passwordRequireUppercase'), DEFAULT_PASSWORD_POLICY.requireUppercase),
      requireLowercase: this.coerceBoolean(map.get('passwordRequireLowercase'), DEFAULT_PASSWORD_POLICY.requireLowercase),
      requireNumber: this.coerceBoolean(map.get('passwordRequireNumber'), DEFAULT_PASSWORD_POLICY.requireNumber),
      requireSymbol: this.coerceBoolean(map.get('passwordRequireSymbol'), DEFAULT_PASSWORD_POLICY.requireSymbol),
      expiryDays,
      historyCount: this.coerceNumber(map.get('passwordHistoryLimit'), DEFAULT_PASSWORD_POLICY.historyCount),
      minScore: this.coerceNumber(map.get('passwordMinScore'), DEFAULT_PASSWORD_POLICY.minScore),
    };
  }

  private buildPasswordHistory(entries: PasswordHistory[]): SecurityPasswordHistoryEntry[] {
    if (!entries.length) {
      const now = new Date().toISOString();
      return [{ id: 'placeholder-password', changedAt: now, location: null, client: 'Account password' }];
    }
    return entries.map((entry, index) => ({
      id: entry.id || `password-${index}`,
      changedAt: entry.createdAt.toISOString(),
      location: null,
      client: 'Account password',
    }));
  }

  private buildSessionResponse(tokens: RefreshTokenWithDevice[], devices?: UserDevice[]): SecuritySessionsPayload {
    if (!tokens.length) {
      return {
        summary: { activeCount: 0, trustedCount: 0, lastRotationAt: null, lastUntrustedAt: null },
        list: [],
      };
    }

    const deviceMap = new Map<string, UserDevice>();
    if (Array.isArray(devices)) {
      for (const device of devices) {
        if (device.id) deviceMap.set(device.id, device);
      }
    }

    const list = tokens.map((token, index) => {
      const parsed = this.parseUserAgent(token.userAgent);
      const device = token.device ?? (token.deviceId ? deviceMap.get(token.deviceId) ?? null : null);
      const trusted = Boolean(device?.trustedAt);
      const risk: SecuritySessionRisk = trusted ? 'low' : 'medium';
      const ipAddress = token.ipAddress ?? device?.ipAddress ?? null;
      const location = parsed.location ?? (ipAddress ? this.deriveLocation(ipAddress) : null);
      return {
        id: token.id,
        device: device?.label ?? parsed.device,
        platform: device?.platform ?? parsed.platform,
        browser: parsed.browser,
        ipAddress,
        location,
        createdAt: token.createdAt.toISOString(),
        lastActiveAt: (token.expiresAt ?? token.createdAt).toISOString(),
        trusted,
        current: index === 0,
        risk,
      } as SecuritySession;
    });

    const summary: SecuritySessionSummary = {
      activeCount: list.length,
      trustedCount: list.filter(item => item.trusted).length,
      lastRotationAt: list[0]?.createdAt ?? null,
      lastUntrustedAt: list.find(item => !item.trusted)?.createdAt ?? null,
    };

    return { summary, list };
  }

  private buildRiskAlerts(logs: AuditLog[]): SecurityRiskAlert[] {
    if (!logs.length) return [];
    return logs
      .filter(log => log.action?.startsWith('auth.'))
      .slice(0, 3)
      .map((log, index) => ({
        id: log.id || `risk-${index}`,
        message: this.describeAuditAction(log.action),
        severity: log.action.includes('lock') || log.action.includes('throttled') ? 'warning' : 'info',
        createdAt: log.createdAt.toISOString(),
        acknowledgedAt: null,
      }));
  }

  private buildSecurityEvents(logs: AuditLog[]): SecurityEventEntry[] {
    return logs.slice(0, 15).map((log, index) => ({
      id: log.id || `event-${index}`,
      action: log.action,
      description: this.describeAuditAction(log.action),
      severity: log.action.includes('lock') ? 'warning' : 'info',
      createdAt: log.createdAt.toISOString(),
      ipAddress: log.ipAddress ?? null,
      location: log.ipAddress ? this.deriveLocation(log.ipAddress) : null,
      metadata: (log.metadata as JsonValue) ?? null,
    }));
  }

  private buildOverview(user: User, sessions: SecuritySessionsPayload, history: SecurityPasswordHistoryEntry[], riskAlerts: SecurityRiskAlert[], factors: SecurityMfaFactor[], devices?: UserDevice[]): SecurityOverview {
    const lastPasswordChange = history[0]?.changedAt ?? (user.updatedAt ? user.updatedAt.toISOString() : null);
    const passwordHealth = this.derivePasswordHealth(lastPasswordChange);
    const trustedDevices = devices?.filter(device => device.trustedAt).length ?? sessions.list.filter(session => session.trusted).length;
    const totalDevices = devices?.length ?? sessions.list.length;
    const untrustedDevices = Math.max(totalDevices - trustedDevices, 0);
    let score = 40;
    if (passwordHealth === 'strong') score += 20;
    else if (passwordHealth === 'fair') score += 10;
    if (factors.some(f => f.enabled)) score += 20;
    if (!riskAlerts.length) score += 10;
    score += Math.min(trustedDevices * 5, 10);
    score = Math.min(95, Math.max(30, score));
    const tier: SecurityScoreTier = score >= 80 ? 'high' : score >= 60 ? 'medium' : 'low';
    const summaryParts: string[] = [];
    summaryParts.push(passwordHealth === 'strong' ? 'Password meets current policy.' : 'Update your password to improve strength.');
    summaryParts.push(factors.some(f => f.enabled) ? 'MFA is enabled on your account.' : 'Enable MFA to further harden sign-in.');
    if (riskAlerts.length) summaryParts.push(`${riskAlerts.length} alert${riskAlerts.length > 1 ? 's' : ''} need review.`);

    return {
      score,
      tier,
      summary: summaryParts.join(' '),
      lastPasswordChange,
      passwordHealth,
      mfaEnabled: factors.some(f => f.enabled),
      trustedDevices,
      untrustedDevices,
      pendingAlerts: riskAlerts.length,
      lastAnomalyAt: riskAlerts[0]?.createdAt ?? null,
      riskAlerts,
    };
  }

  private buildMfaSnapshot(metadataSnapshot: AccountSecuritySnapshot['mfa'], dbFactors: UserMfaFactor[], backupCodes: UserBackupCode[]): AccountSecuritySnapshot['mfa'] {
    if (!dbFactors.length) {
      if (!backupCodes.length) return metadataSnapshot;
      const backupSummary = this.summarizeBackupCodes(backupCodes);
      const factors = metadataSnapshot.factors.map(factor => (
        factor.type === 'backup_codes'
          ? { ...factor, enabled: backupSummary.unusedCount > 0, remainingCodes: backupSummary.unusedCount }
          : factor
      ));
      return { ...metadataSnapshot, factors };
    }

    const backupSummary = this.summarizeBackupCodes(backupCodes);
    const factors = dbFactors.map(factor => this.mapDbFactorToSnapshot(factor, backupSummary.perFactor.get(factor.id) ?? null));
    if (!factors.some(factor => factor.type === 'backup_codes')) {
      factors.push({
        id: 'backup-codes',
        type: 'backup_codes',
        label: 'Backup codes',
        enabled: backupSummary.unusedCount > 0,
        status: backupSummary.unusedCount > 0 ? 'active' : 'disabled',
        enrolledAt: backupSummary.latestCreatedAt?.toISOString() ?? null,
        lastUsedAt: null,
        devices: [],
        remainingCodes: backupSummary.unusedCount,
        metadata: null,
      });
    } else if (backupSummary.unusedCount > 0) {
      factors.forEach(factor => {
        if (factor.type === 'backup_codes') {
          factor.enabled = true;
          factor.status = 'active';
          factor.remainingCodes = backupSummary.unusedCount;
          factor.enrolledAt = factor.enrolledAt ?? backupSummary.latestCreatedAt?.toISOString() ?? null;
        }
      });
    } else {
      factors.forEach(factor => {
        if (factor.type === 'backup_codes') {
          factor.enabled = false;
          factor.status = 'disabled';
        }
      });
    }

    const recommendations = metadataSnapshot?.recommendations?.length
      ? metadataSnapshot.recommendations
      : DEFAULT_RECOMMENDATIONS.map(rec => ({ ...rec }));

    return { factors, recommendations };
  }

  private mergeRecoveryWithBackupCodes(recovery: SecurityRecoverySettings, backupCodes: UserBackupCode[]): SecurityRecoverySettings {
    if (!backupCodes.length) return recovery;
    const summary = this.summarizeBackupCodes(backupCodes);
    return {
      ...recovery,
      backupCodesRemaining: summary.unusedCount,
      lastCodesGeneratedAt: summary.latestCreatedAt?.toISOString() ?? recovery.lastCodesGeneratedAt ?? null,
    };
  }

  private summarizeBackupCodes(backupCodes: UserBackupCode[]): { total: number; unusedCount: number; perFactor: Map<string, number>; latestCreatedAt: Date | null } {
    let latest: Date | null = null;
    let unusedCount = 0;
    const perFactor = new Map<string, number>();
    for (const code of backupCodes) {
      if (!latest || code.createdAt > latest) {
        latest = code.createdAt;
      }
      if (!code.usedAt) {
        unusedCount += 1;
        if (code.factorId) {
          perFactor.set(code.factorId, (perFactor.get(code.factorId) ?? 0) + 1);
        }
      }
    }
    return { total: backupCodes.length, unusedCount, perFactor, latestCreatedAt: latest };
  }

  private mapDbFactorToSnapshot(factor: UserMfaFactor, remainingCodes: number | null): SecurityMfaFactor {
    const type = this.mapDbFactorType(factor.type);
    const devices = Array.isArray(factor.devices)
      ? (factor.devices as unknown[]).map((device, index) => this.normalizeHardwareKey(device, index))
      : [];
    return {
      id: factor.id,
      type,
      label: factor.label ?? (type === 'totp' ? DEFAULT_TOTP_LABEL : type.toUpperCase()),
      enabled: factor.enabled,
      status: this.mapDbFactorStatus(factor.status),
      enrolledAt: factor.enrolledAt?.toISOString() ?? null,
      lastUsedAt: factor.lastUsedAt?.toISOString() ?? null,
      devices,
      remainingCodes,
      metadata: (factor.metadata as JsonValue) ?? null,
    } satisfies SecurityMfaFactor;
  }

  private mapDbFactorType(type: string): SecurityMfaFactorType {
    switch (type) {
      case 'SMS': return 'sms';
      case 'PUSH': return 'push';
      case 'HARDWARE_KEY': return 'hardware_key';
      case 'BACKUP_CODES': return 'backup_codes';
      default: return 'totp';
    }
  }

  private mapDbFactorStatus(status: unknown): SecurityMfaFactorStatus {
    switch (status) {
      case 'PENDING':
        return 'pending';
      case 'DISABLED':
        return 'disabled';
      case 'REVOKED':
        return 'revoked';
      default:
        return 'active';
    }
  }

  private normalizeSecurityFactorStatus(value: unknown, fallback: SecurityMfaFactorStatus): SecurityMfaFactorStatus {
    if (value === 'pending' || value === 'active' || value === 'disabled' || value === 'revoked') {
      return value;
    }
    return fallback;
  }

  private derivePasswordHealth(lastChange: string | null | undefined): SecurityPasswordHealth {
    if (!lastChange) return 'unknown';
    const last = new Date(lastChange).getTime();
    const diffDays = Math.floor((Date.now() - last) / MILLISECONDS_PER_DAY);
    if (Number.isNaN(diffDays)) return 'unknown';
    if (diffDays < 90) return 'strong';
    if (diffDays < 365) return 'fair';
    return 'weak';
  }

  private extractSecurityMetadata(user: User): { mfa: AccountSecuritySnapshot['mfa']; recovery: unknown; alerts: unknown } {
    const metadata = this.asRecord((user as unknown as { metadata?: Prisma.JsonValue | null }).metadata) ?? {};
    const security = this.asRecord(metadata.security) ?? metadata;
    const notifications = this.asRecord(metadata.notifications) ?? null;
    const mfa = this.normalizeMfaSettings(security.mfa);
    const recovery = security.recovery ?? null;
    let alerts = security.alerts ?? null;
    if (!alerts && notifications) {
      alerts = this.buildAlertsFromNotificationTopics(notifications) ?? null;
    }
    return { mfa, recovery, alerts };
  }

  private normalizeMfaSettings(raw: unknown): AccountSecuritySnapshot['mfa'] {
    const record = this.asRecord(raw);
    const rawFactors = Array.isArray(record?.factors) ? (record?.factors as unknown[]) : [];
    const factors = rawFactors.map((factor, index) => this.normalizeMfaFactor(factor, index));
    const rawRecommendations = Array.isArray(record?.recommendations) ? (record?.recommendations as unknown[]) : [];
    const recommendations = rawRecommendations.length
      ? rawRecommendations.map((rec, index) => this.normalizeRecommendation(rec, index))
      : DEFAULT_RECOMMENDATIONS.map(rec => ({ ...rec }));

    if (!factors.length) {
      factors.push({
        id: 'totp-placeholder',
        type: 'totp',
        label: DEFAULT_TOTP_LABEL,
        enabled: false,
        status: 'disabled',
        enrolledAt: null,
        lastUsedAt: null,
        devices: [],
        remainingCodes: null,
        metadata: null,
      });
    }

    return { factors, recommendations };
  }

  private normalizeRecommendation(value: unknown, index: number): SecurityMfaRecommendation {
    if (!value || typeof value !== 'object') return DEFAULT_RECOMMENDATIONS[Math.min(index, DEFAULT_RECOMMENDATIONS.length - 1)];
    const record = value as Record<string, unknown>;
    const type: SecurityMfaFactorType = record.type === 'sms' || record.type === 'push' || record.type === 'hardware_key' || record.type === 'backup_codes' ? record.type : 'totp';
    return {
      type,
      reason: this.coerceString(record.reason, 'Complete this MFA recommendation'),
    };
  }

  private normalizeMfaFactor(value: unknown, index: number): SecurityMfaFactor {
    if (!value || typeof value !== 'object') {
      return {
        id: `factor-${index}`,
        type: 'totp',
        label: DEFAULT_TOTP_LABEL,
        enabled: false,
        status: 'disabled',
        enrolledAt: null,
        lastUsedAt: null,
        devices: [],
        remainingCodes: null,
        metadata: null,
      };
    }
    const record = value as Record<string, unknown>;
    const type: SecurityMfaFactorType = record.type === 'sms' || record.type === 'push' || record.type === 'hardware_key' || record.type === 'backup_codes' ? record.type : 'totp';
    const devices = Array.isArray(record.devices)
      ? record.devices.map((device, deviceIndex) => this.normalizeHardwareKey(device, deviceIndex))
      : [];
    const enabled = this.coerceBoolean(record.enabled, true);
    return {
      id: this.coerceString(record.id, `factor-${index}`),
      type,
      label: this.coerceString(record.label, type === 'totp' ? DEFAULT_TOTP_LABEL : type.toUpperCase()),
      enabled,
      status: this.normalizeSecurityFactorStatus(record.status, enabled ? 'active' : 'disabled'),
      enrolledAt: this.coerceDate(record.enrolledAt),
      lastUsedAt: this.coerceDate(record.lastUsedAt),
      devices,
      remainingCodes: record.remainingCodes == null ? null : this.coerceNumber(record.remainingCodes, 0),
      metadata: (record.metadata as JsonValue) ?? null,
    };
  }

  private normalizeHardwareKey(value: unknown, index: number): SecurityHardwareKey {
    if (!value || typeof value !== 'object') {
      return {
        id: `hw-${index}`,
        label: 'Security key',
        addedAt: null,
        lastUsedAt: null,
        transports: [],
      };
    }
    const record = value as Record<string, unknown>;
    return {
      id: this.coerceString(record.id, `hw-${index}`),
      label: this.coerceString(record.label, 'Security key'),
      addedAt: this.coerceDate(record.addedAt),
      lastUsedAt: this.coerceDate(record.lastUsedAt),
      transports: this.coerceStringArray(record.transports, []),
    };
  }

  private normalizeRecoverySettings(raw: unknown, user: User): SecurityRecoverySettings {
    const record = this.asRecord(raw);
    if (!record) {
      return {
        ...DEFAULT_RECOVERY_SETTINGS,
        primaryEmail: {
          type: 'email',
          value: user.email ?? 'unknown@example.com',
          verified: Boolean(user.emailVerified),
          lastVerifiedAt: user.emailVerified ? user.emailVerified.toISOString() : null,
        },
      };
    }

    return {
      primaryEmail: this.normalizeRecoveryChannel(record.primaryEmail, {
        type: 'email',
        value: user.email ?? 'unknown@example.com',
        verified: Boolean(user.emailVerified),
        lastVerifiedAt: user.emailVerified ? user.emailVerified.toISOString() : null,
      }),
      backupEmail: record.backupEmail ? this.normalizeRecoveryChannel(record.backupEmail, DEFAULT_RECOVERY_CHANNEL) : undefined,
      sms: record.sms ? this.normalizeRecoveryChannel(record.sms, { ...DEFAULT_RECOVERY_CHANNEL, type: 'sms' }) : undefined,
      backupCodesRemaining: this.coerceNumber(record.backupCodesRemaining, DEFAULT_RECOVERY_SETTINGS.backupCodesRemaining),
      lastCodesGeneratedAt: this.coerceDate(record.lastCodesGeneratedAt),
      contacts: Array.isArray(record.contacts)
        ? record.contacts.map((contact, index) => this.normalizeBreakGlassContact(contact, index))
        : [],
    };
  }

  private normalizeRecoveryChannel(value: unknown, fallback: SecurityRecoveryChannel): SecurityRecoveryChannel {
    if (!value || typeof value !== 'object') return { ...fallback };
    const record = value as Record<string, unknown>;
    const type = record.type === 'sms' ? 'sms' : 'email';
    return {
      type,
      value: this.coerceString(record.value, fallback.value),
      verified: this.coerceBoolean(record.verified, fallback.verified),
      lastVerifiedAt: this.coerceDate(record.lastVerifiedAt) ?? fallback.lastVerifiedAt ?? null,
    };
  }

  private normalizeBreakGlassContact(value: unknown, index: number): SecurityBreakGlassContact {
    if (!value || typeof value !== 'object') {
      return {
        id: `contact-${index}`,
        name: 'Backup contact',
        email: 'contact@example.com',
        phone: null,
        verified: false,
      };
    }
    const record = value as Record<string, unknown>;
    return {
      id: this.coerceString(record.id, `contact-${index}`),
      name: this.coerceString(record.name, 'Backup contact'),
      email: this.coerceString(record.email, 'contact@example.com'),
      phone: record.phone ? this.coerceString(record.phone) : null,
      verified: this.coerceBoolean(record.verified, false),
    };
  }

  private normalizeAlertSettings(raw: unknown): SecurityAlertSettings {
    const record = this.asRecord(raw);
    if (!record) {
      return {
        preferences: DEFAULT_ALERT_PREFERENCES.map(pref => ({ ...pref, channels: [...pref.channels] })),
        defaultChannels: ['email'],
      };
    }
    return {
      preferences: Array.isArray(record.preferences)
        ? record.preferences.map((pref, index) => this.normalizeAlertPreference(pref, index))
        : DEFAULT_ALERT_PREFERENCES.map(pref => ({ ...pref, channels: [...pref.channels] })),
      defaultChannels: this.coerceAlertChannels(record.defaultChannels, ['email']),
    };
  }

  private normalizeAlertPreference(value: unknown, index: number): SecurityAlertPreference {
    if (!value || typeof value !== 'object') {
      return { ...DEFAULT_ALERT_PREFERENCES[index % DEFAULT_ALERT_PREFERENCES.length], channels: ['email'] };
    }
    const record = value as Record<string, unknown>;
    return {
      event: this.coerceString(record.event, `custom-${index}`),
      label: this.coerceString(record.label, `Alert ${index + 1}`),
      enabled: this.coerceBoolean(record.enabled, true),
      channels: this.coerceAlertChannels(record.channels, ['email']),
    };
  }

  private buildAlertsFromNotificationTopics(value: Record<string, any>): SecurityAlertSettings | null {
    if (!value) return null;
    const topics: unknown[] = Array.isArray(value.topics) ? value.topics : [];
    const securityTopics = topics
      .map(topic => this.asRecord(topic))
      .filter((record): record is Record<string, unknown> => Boolean(record && record.category === 'security'));
    if (!securityTopics.length) return null;
    const preferences = securityTopics.map((topic, index) => {
      const record = topic;
      return {
        event: this.coerceString(record.id, `notification-security-${index}`),
        label: this.coerceString(record.label, 'Security alert'),
        enabled: this.coerceBoolean(record.enabled, true),
        channels: this.coerceAlertChannels(record.channels, ['email']),
      } satisfies SecurityAlertPreference;
    });
    if (!preferences.length) return null;
    return {
      preferences,
      defaultChannels: this.coerceAlertChannels(value.defaultChannels, ['email']),
    } satisfies SecurityAlertSettings;
  }

  private parseUserAgent(userAgent?: string | null): { device: string; platform: string | null; browser: string | null; location: string | null } {
    if (!userAgent) return { device: 'Browser session', platform: null, browser: null, location: null };
    const ua = userAgent.toLowerCase();
    let device = 'Browser session';
    if (ua.includes('iphone')) device = 'iPhone';
    else if (ua.includes('ipad')) device = 'iPad';
    else if (ua.includes('android')) device = 'Android device';
    else if (ua.includes('mac os')) device = 'Mac';
    else if (ua.includes('windows')) device = 'Windows PC';
    else if (ua.includes('linux')) device = 'Linux workstation';

    let platform: string | null = null;
    if (ua.includes('mac os')) platform = 'macOS';
    else if (ua.includes('windows')) platform = 'Windows';
    else if (ua.includes('android')) platform = 'Android';
    else if (ua.includes('iphone') || ua.includes('ipad')) platform = 'iOS';
    else if (ua.includes('linux')) platform = 'Linux';

    let browser: string | null = null;
    if (ua.includes('chrome')) browser = 'Chrome';
    else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari';
    else if (ua.includes('firefox')) browser = 'Firefox';
    else if (ua.includes('edge')) browser = 'Edge';

    return { device, platform, browser, location: null };
  }

  private deriveLocation(ip: string): string | null {
    if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.')) return 'Private network';
    if (ip === '127.0.0.1') return 'Localhost';
    return null;
  }

  private describeAuditAction(action: string): string {
    if (action.includes('login')) return 'Login activity detected';
    if (action.includes('logout')) return 'Logout activity recorded';
    if (action.includes('password')) return 'Password activity recorded';
    if (action.includes('mfa')) return 'MFA event recorded';
    return 'Security event recorded';
  }

  private coerceNumber(value: unknown, fallback: number): number {
    const num = Number(value);
    return Number.isFinite(num) ? num : fallback;
  }

  private coerceBoolean(value: unknown, fallback: boolean): boolean {
    if (typeof value === 'boolean') return value;
    if (value === 'true') return true;
    if (value === 'false') return false;
    return fallback;
  }

  private coerceString(value: unknown, fallback = ''): string {
    if (typeof value === 'string') return value;
    if (typeof value === 'number') return String(value);
    return fallback;
  }

  private coerceDate(value: unknown): string | null {
    const date = value instanceof Date
      ? value
      : typeof value === 'string' && value.trim().length
        ? new Date(value)
        : null;
    if (!date) return null;
    const epoch = date.getTime();
    if (Number.isNaN(epoch)) return null;
    try {
      return date.toISOString();
    } catch {
      return null;
    }
  }

  private coerceStringArray(value: unknown, fallback: string[]): string[] {
    if (Array.isArray(value)) {
      return value
        .map(entry => (typeof entry === 'string' ? entry : String(entry ?? '')))
        .map(entry => entry.trim())
        .filter(Boolean);
    }
    if (typeof value === 'string') {
      return value
        .split(/,|\n/)
        .map(entry => entry.trim())
        .filter(Boolean);
    }
    return [...fallback];
  }

  private coerceAlertChannels(value: unknown, fallback: SecurityAlertChannel[]): SecurityAlertChannel[] {
    if (!Array.isArray(value)) return [...fallback];
    return value
      .map(entry => (typeof entry === 'string' ? entry : null))
      .filter((entry): entry is string => Boolean(entry))
      .map(entry => (entry === 'sms' || entry === 'push' || entry === 'in_app' ? entry : 'email')) as SecurityAlertChannel[];
  }

  private asRecord(value: unknown): Record<string, any> | null {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    return value as Record<string, any>;
  }

  private mergeRecoverySettings(existing: SecurityRecoverySettings, updates: SecurityRecoverySettingsInput): Record<string, unknown> {
    const mergedContacts = (updates.contacts ?? existing.contacts).map(contact => ({ ...contact }));
    const result: Record<string, unknown> = {
      backupCodesRemaining: updates.backupCodesRemaining ?? existing.backupCodesRemaining,
      lastCodesGeneratedAt: updates.lastCodesGeneratedAt === null
        ? null
        : updates.lastCodesGeneratedAt ?? existing.lastCodesGeneratedAt ?? null,
      contacts: mergedContacts,
    };

    result.primaryEmail = { ...existing.primaryEmail, ...updates.primaryEmail, type: 'email' };

    if (updates.backupEmail === null) {
      // Explicit removal
    } else if (updates.backupEmail) {
      result.backupEmail = { ...(existing.backupEmail ?? DEFAULT_RECOVERY_CHANNEL), ...updates.backupEmail, type: 'email' };
    } else if (existing.backupEmail) {
      result.backupEmail = { ...existing.backupEmail, type: 'email' };
    }

    if (updates.sms === null) {
      // Remove sms channel
    } else if (updates.sms) {
      result.sms = { ...(existing.sms ?? { ...DEFAULT_RECOVERY_CHANNEL, type: 'sms' }), ...updates.sms, type: 'sms' };
    } else if (existing.sms) {
      result.sms = { ...existing.sms, type: 'sms' };
    }

    return result;
  }

  private mergeAlertSettings(existing: SecurityAlertSettings, updates: SecurityAlertSettingsInput): Record<string, unknown> {
    const preferencesSource = Array.isArray(updates.preferences)
      ? updates.preferences
      : existing.preferences;
    const defaultChannelsSource = Array.isArray(updates.defaultChannels)
      ? updates.defaultChannels
      : existing.defaultChannels;

    return {
      preferences: preferencesSource.map(pref => ({ ...pref, channels: pref.channels ? [...pref.channels] : undefined })),
      defaultChannels: [...defaultChannelsSource],
    };
  }

  private readPendingTotp(security: Record<string, any>): PendingTotpEnrollment | null {
    const pending = this.asRecord(security.pendingTotp);
    if (!pending) return null;
    const ticket = this.coerceString(pending.ticket);
    const factorId = this.coerceString(pending.factorId);
    if (!ticket || !factorId) return null;
    const mode: PendingTotpEnrollment['mode'] = pending.mode === 'rotate' ? 'rotate' : 'create';
    const expiresAt = this.coerceString(pending.expiresAt) || null;
    return { ticket, factorId, mode, expiresAt };
  }

  private async discardPendingTotp(userId: string, pending: PendingTotpEnrollment | null): Promise<void> {
    if (!pending) return;
    const factor = await this.prisma.userMfaFactor.findFirst({ where: { id: pending.factorId, userId } });
    if (!factor) return;
    if (pending.mode === 'create' && factor.status === 'PENDING') {
      await this.prisma.userMfaFactor.delete({ where: { id: factor.id } }).catch(() => {});
      await this.prisma.userBackupCode.deleteMany({ where: { factorId: factor.id } }).catch(() => {});
      return;
    }
    const metadata = this.cloneMetadata((factor as unknown as { metadata?: Prisma.JsonValue | null }).metadata ?? null);
    const cleanedMetadata = this.prepareMetadataPayload(this.stripEnrollmentMetadata(metadata));
    await this.prisma.userMfaFactor.update({ where: { id: factor.id }, data: { metadata: cleanedMetadata } }).catch(() => {});
  }

  private stripEnrollmentMetadata(metadata: Record<string, any> | null): Record<string, any> | null {
    if (!metadata) return null;
    if (!Object.prototype.hasOwnProperty.call(metadata, 'enrollment')) return metadata;
    const clone = { ...metadata };
    delete clone.enrollment;
    return Object.keys(clone).length ? clone : null;
  }

  private prepareMetadataPayload(metadata: Record<string, any> | null): Prisma.InputJsonValue | typeof Prisma.JsonNull {
    if (!metadata || !Object.keys(metadata).length) {
      return Prisma.JsonNull;
    }
    return metadata as Prisma.InputJsonValue;
  }

  private normalizeFactorLabel(label?: string | null): string | null {
    if (typeof label !== 'string') return null;
    const trimmed = label.trim();
    return trimmed.length ? trimmed : null;
  }

  private normalizeLabelKey(label?: string | null): string | null {
    const normalized = this.normalizeFactorLabel(label);
    return normalized ? normalized.toLowerCase() : null;
  }

  private async findTotpFactorByLabel(userId: string, label: string): Promise<UserMfaFactor | null> {
    const key = this.normalizeLabelKey(label);
    if (!key) return null;
    const factors = await this.prisma.userMfaFactor.findMany({
      where: { userId, type: 'TOTP', status: { not: 'REVOKED' } },
    });
    return factors.find(factor => this.normalizeLabelKey(factor.label) === key) ?? null;
  }

  private async chooseTotpLabel(userId: string, preferred?: string | null): Promise<string> {
    const normalized = this.normalizeFactorLabel(preferred);
    if (normalized) return normalized;
    const count = await this.prisma.userMfaFactor.count({ where: { userId, type: 'TOTP', status: { not: 'REVOKED' } } });
    if (count <= 0) return DEFAULT_TOTP_LABEL;
    return `${DEFAULT_TOTP_LABEL} #${count + 1}`;
  }

  private generateBackupCodes(): { codes: string[]; hashed: { code: string; hash: string }[] } {
    const codes: string[] = [];
    const hashed: { code: string; hash: string }[] = [];
    for (let i = 0; i < BACKUP_CODE_COUNT; i += 1) {
      const code = this.createBackupCode();
      codes.push(code);
      hashed.push({ code, hash: this.hashBackupCode(code) });
    }
    return { codes, hashed };
  }

  private createBackupCode(): string {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const desiredLength = BACKUP_CODE_GROUP_LENGTH * 2;
    const buffer = randomBytes(desiredLength);
    let raw = '';
    for (let i = 0; i < desiredLength; i += 1) {
      raw += alphabet[buffer[i] % alphabet.length];
    }
    return raw.match(new RegExp(`.{1,${BACKUP_CODE_GROUP_LENGTH}}`, 'g'))?.join('-') ?? raw;
  }

  private hashBackupCode(code: string): string {
    return createHash('sha256').update(code).digest('hex');
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

  private async revokeOtherRefreshTokens(userId: string, currentToken?: string | null): Promise<void> {
    const where: Prisma.RefreshTokenWhereInput = { userId, revokedAt: null };
    if (currentToken) {
      where.token = { not: currentToken };
    }
    await this.prisma.refreshToken.updateMany({ where, data: { revokedAt: new Date() } }).catch(() => {});
  }
}
