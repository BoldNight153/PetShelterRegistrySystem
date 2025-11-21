import { Router, type Request, type Response, type NextFunction, type RequestHandler } from 'express';
import crypto from 'crypto';
import { prismaClient as prisma } from '../prisma/client';
import argon2 from 'argon2';
import jwt, { SignOptions, Secret } from 'jsonwebtoken';
import { resetPasswordEmailTemplate, sendMail, verificationEmailTemplate } from '../lib/email';
import { getCount as libGetCount, incrementAndCheck as libIncrementAndCheck, resetWindow as libResetWindow } from '../lib/rateLimit';
import type { RateLimitService } from '../services/rateLimitService';
import type { AuthService } from '../services/authService';
import { PasswordChangeError, SecurityOperationError, SecurityService } from '../services/securityService';
import { NotificationService } from '../services/notificationService';
import { Prisma, type User, type UserDevice, type UserMfaFactor, type UserBackupCode } from '@prisma/client';
import { verifyTotpCode } from '../lib/totp';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth';
import { meetsRegistrationPasswordRequirements } from '../lib/passwordPolicy';
import bcrypt from 'bcryptjs';

// uses centralized prisma client from /src/prisma/client.ts

// Deduped constants for lint rules
const INTERNAL_ERROR = 'internal error';
const HEADER_UA = 'user-agent';
const HEADER_CSRF = 'x-csrf-token';
const INVALID_TOKEN = 'invalid token';
const AUDIT_LOGIN_LOCKED = 'auth.login.locked_user';
const DIAG_VALIDATE_CSRF_MISSING = 'diagnostic /validateCsrf missing';
const ERROR_INVALID_PAYLOAD = 'invalid payload';
const ERROR_USER_NOT_FOUND = 'user not found';
const WARN_RATE_LIMIT_INCREMENT = 'rateLimit.incrementAndCheck failed, falling back';
const ERROR_FACTOR_ID_REQUIRED = 'factor id required';

const router = Router();
const LEGACY_BCRYPT_REGEX = /^\$2[aby]\$/;

const UpdateProfileSchema = z.object({
  name: z.string().min(1).max(120).trim().optional().nullable(),
  avatarUrl: z.string().url().max(2048).optional().nullable(),
  title: z.string().trim().max(120).optional().nullable(),
  department: z.string().trim().max(120).optional().nullable(),
  pronouns: z.string().trim().max(60).optional().nullable(),
  timezone: z.string().trim().max(80).optional().nullable(),
  locale: z.string().trim().max(20).optional().nullable(),
  phone: z.string().trim().max(40).optional().nullable(),
  bio: z.string().trim().max(1000).optional().nullable(),
});

const RecoveryChannelSchema = z.object({
  type: z.enum(['email', 'sms']),
  value: z.string().trim().min(1).max(320),
  verified: z.boolean().optional(),
  lastVerifiedAt: z.string().datetime().optional().nullable(),
});

const BreakGlassContactSchema = z.object({
  id: z.string().trim().min(1).max(120).optional(),
  name: z.string().trim().min(1).max(120),
  email: z.string().trim().email().max(320),
  phone: z.string().trim().min(3).max(40).optional().nullable(),
  verified: z.boolean().optional(),
});

const AlertPreferenceSchema = z.object({
  event: z.string().trim().min(1).max(120),
  label: z.string().trim().min(1).max(160),
  enabled: z.boolean(),
  channels: z.array(z.enum(['email', 'sms', 'push', 'in_app'])).min(1).max(4),
});

const UpdateRecoverySchema = z.object({
  primaryEmail: RecoveryChannelSchema.extend({ type: z.literal('email'), value: z.string().trim().email().max(320) }),
  backupEmail: RecoveryChannelSchema.extend({ type: z.literal('email'), value: z.string().trim().email().max(320) }).optional().nullable(),
  sms: RecoveryChannelSchema.extend({
    type: z.literal('sms'),
    value: z.string().trim().min(6).max(40),
  }).optional().nullable(),
  backupCodesRemaining: z.number().int().min(0).max(50).optional(),
  lastCodesGeneratedAt: z.string().datetime().optional().nullable(),
  contacts: z.array(BreakGlassContactSchema).max(5).optional(),
});

const UpdateAlertsSchema = z.object({
  preferences: z.array(AlertPreferenceSchema).min(1).max(25),
  defaultChannels: z.array(z.enum(['email', 'sms', 'push', 'in_app'])).min(1).max(4),
});

const ChangePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'current password is required').max(256),
  newPassword: z.string().min(8, 'new password must be at least 8 characters').max(256),
  signOutOthers: z.boolean().optional().default(true),
});

const RevokeSessionSchema = z.object({
  sessionId: z.string().trim().min(10).max(200),
});

const TrustSessionSchema = z.object({
  sessionId: z.string().trim().min(10).max(200),
  trust: z.boolean().optional().default(true),
});

const TotpEnrollSchema = z.object({
  label: z.string().trim().min(1).max(120).optional(),
  issuer: z.string().trim().min(1).max(160).optional(),
  accountName: z.string().trim().min(1).max(160).optional(),
});

const TotpConfirmSchema = z.object({
  ticket: z.string().trim().min(16).max(200),
  code: z.string().trim().min(6).max(12),
});

const TotpRotateSchema = z.object({
  label: z.string().trim().min(1).max(120).optional(),
  issuer: z.string().trim().min(1).max(160).optional(),
  accountName: z.string().trim().min(1).max(160).optional(),
});

const BackupCodesRegenerateSchema = z.object({
  factorId: z.string().trim().min(1).max(200).optional(),
});

const NotificationChannelSchema = z.enum(['email', 'sms', 'push', 'in_app']);
const NotificationTopicCategorySchema = z.enum(['account', 'animals', 'operations', 'security', 'system']);
const NotificationDevicePlatformSchema = z.enum(['ios', 'android', 'web', 'unknown']);

const NotificationTopicSchema = z.object({
  id: z.string().trim().min(1).max(160),
  label: z.string().trim().min(1).max(160),
  description: z.string().trim().max(240).optional().nullable(),
  category: NotificationTopicCategorySchema,
  enabled: z.boolean(),
  channels: z.array(NotificationChannelSchema).min(1).max(4),
  critical: z.boolean().optional(),
  muteUntil: z.string().datetime().optional().nullable(),
});

const NotificationDigestSchema = z.object({
  enabled: z.boolean(),
  frequency: z.enum(['daily', 'weekly']),
  sendHourLocal: z.number().int().min(0).max(23),
  timezone: z.string().trim().min(2).max(60).optional().nullable(),
  includeSummary: z.boolean(),
});

const NotificationQuietHoursSchema = z.object({
  enabled: z.boolean(),
  startHour: z.number().int().min(0).max(23),
  endHour: z.number().int().min(0).max(23),
  timezone: z.string().trim().min(2).max(60).optional().nullable(),
});

const NotificationEscalationsSchema = z.object({
  smsFallback: z.boolean(),
  backupEmail: z.string().trim().email().optional().nullable(),
  pagerDutyWebhook: z.string().trim().url().optional().nullable(),
});

const NotificationDeviceSchema = z.object({
  id: z.string().trim().min(1).max(160),
  label: z.string().trim().min(1).max(160),
  platform: NotificationDevicePlatformSchema,
  enabled: z.boolean(),
  lastUsedAt: z.string().datetime().optional().nullable(),
});

const NotificationSettingsSchema = z.object({
  defaultChannels: z.array(NotificationChannelSchema).min(1).max(4),
  topics: z.array(NotificationTopicSchema).min(1).max(50),
  digests: NotificationDigestSchema,
  quietHours: NotificationQuietHoursSchema,
  criticalEscalations: NotificationEscalationsSchema,
  devices: z.array(NotificationDeviceSchema).max(25),
});

const NotificationSettingsUpdateSchema = z.object({
  defaultChannels: z.array(NotificationChannelSchema).min(1).max(4).optional(),
  topics: z.array(NotificationTopicSchema).min(1).max(50).optional(),
  digests: NotificationDigestSchema.optional(),
  quietHours: NotificationQuietHoursSchema.optional(),
  criticalEscalations: NotificationEscalationsSchema.optional(),
  devices: z.array(NotificationDeviceSchema).max(25).optional(),
});

const HEADER_DEVICE_FP = 'x-device-fingerprint';
const MFA_CHALLENGE_TTL_MS = Number(process.env.MFA_CHALLENGE_TTL_MS ?? 5 * 60 * 1000);

const LoginRequestSchema = z.object({
  email: z.string().trim().min(1).max(320),
  password: z.string().min(1).max(256),
  deviceFingerprint: z.string().trim().min(8).max(200).optional(),
  deviceName: z.string().trim().min(1).max(160).optional(),
  devicePlatform: z.string().trim().min(1).max(160).optional(),
  devicePushToken: z.string().trim().min(1).max(512).optional(),
  trustThisDevice: z.boolean().optional(),
});

const MfaVerifySchema = z.object({
  challengeId: z.string().trim().min(16).max(256),
  code: z.string().trim().min(4).max(16).optional(),
  backupCode: z.string().trim().min(4).max(64).optional(),
  factorId: z.string().trim().min(1).max(200).optional(),
  method: z.enum(['totp', 'backup_code']).optional(),
  trustThisDevice: z.boolean().optional(),
  deviceFingerprint: z.string().trim().min(8).max(200).optional(),
  deviceName: z.string().trim().min(1).max(160).optional(),
  devicePlatform: z.string().trim().min(1).max(160).optional(),
  devicePushToken: z.string().trim().min(1).max(512).optional(),
});

type LoginRequestBody = z.infer<typeof LoginRequestSchema>;
type MfaVerifyBody = z.infer<typeof MfaVerifySchema>;

type ChallengeFactorType = 'totp' | 'sms' | 'push' | 'hardware_key' | 'backup_codes';
type LoginChallengeFactor = {
  id: string;
  type: ChallengeFactorType;
  label: string;
  lastUsedAt?: string | null;
};

type DeviceContext = {
  fingerprint?: string | null;
  label?: string | null;
  platform?: string | null;
  userAgent?: string | null;
  ipAddress?: string | null;
  pushToken?: string | null;
  trustRequested?: boolean;
  trusted?: boolean;
};

type LoginChallengePayload = {
  id: string;
  expiresAt: string;
  reason: 'mfa_required' | 'untrusted_device';
  factors: LoginChallengeFactor[];
  defaultFactorId: string | null;
  device: {
    fingerprint?: string | null;
    label?: string | null;
    platform?: string | null;
    trustRequested: boolean;
    trusted: boolean;
    allowTrust: boolean;
  };
};

type ChallengeMetadata = {
  version: number;
  userId: string;
  email: string;
  loginAt: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  device?: DeviceContext;
  rateLimit?: { scope: string; key: string; windowMs: number };
  factors: LoginChallengeFactor[];
  defaultFactorId?: string | null;
};

function parseUserMetadata(value: unknown): Record<string, unknown> | null {
  if (!value) return null;
  if (typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // ignore malformed JSON stored in legacy rows
    }
  }
  return null;
}

function cloneUserMetadata(value: unknown): Record<string, unknown> {
  const parsed = parseUserMetadata(value);
  return parsed ? { ...parsed } : {};
}

function resolveAuthService(req: any): AuthService | null {
  try { const v = req.container?.resolve('authService'); return v ? (v as AuthService) : null; } catch { return null; }
}

function resolveRateLimitService(req: any): RateLimitService | null {
  try {
    // Try the modern registration name first, then a shorter legacy name if present.
    const v = req.container?.resolve?.('rateLimitService') ?? req.container?.resolve?.('rateLimit');
    return v ? (v as RateLimitService) : null;
  } catch (err) {
    try { (req).log?.warn?.({ err }, 'rateLimit service resolution failed'); } catch {}
    return null;
  }
}

function resolveSecurityService(req: any): SecurityService | null {
  try {
    const svc = req.container?.resolve?.('securityService');
    return svc ? (svc as SecurityService) : null;
  } catch {
    return null;
  }
}

function resolveNotificationService(req: any): NotificationService | null {
  try {
    const svc = req.container?.resolve?.('notificationService');
    return svc ? (svc as NotificationService) : null;
  } catch {
    return null;
  }
}

// Simple andi-CSRF implementation using double-submit cookie pattern.
// GET /auth/csrf - issues a CSRF token and sets a cookie (httpOnly=false) so the browser can send it back via header.
router.get('/csrf', (_req: Request, res: Response) => {
  const secret = process.env.CSRF_SECRET || 'dev-csrf-secret';
  const token = crypto.randomBytes(16).toString('hex');
  // Optionally sign; here we attach a simple HMAC for tamper detection
  const hmac = crypto.createHmac('sha256', secret).update(token).digest('hex');
  const csrfToken = `${token}.${hmac}`;
  // Non-HttpOnly so clients can read and reflect in header; SameSite=Lax is fine
  // Determine secure flag: allow explicit override via COOKIE_SECURE, otherwise
  // require HTTPS-based APP_ORIGIN in production to enable Secure. This avoids
  // accidentally setting Secure=true on localhost HTTP which would prevent
  // cookies from being stored by the browser.
  const cookieSecure = typeof process.env.COOKIE_SECURE !== 'undefined'
    ? String(process.env.COOKIE_SECURE) === 'true'
    : (process.env.NODE_ENV === 'production' && String(process.env.APP_ORIGIN || '').startsWith('https'));

  res.cookie('csrfToken', csrfToken, {
    httpOnly: false,
    secure: cookieSecure,
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000,
    path: '/',
  });
  res.json({ csrfToken });
});

// Middleware to validate CSRF on state-changing requests
function validateCsrf(req: Request, res: Response, next: NextFunction): void {
  const fromCookie = req.cookies?.csrfToken;
  const fromHeader = req.header(HEADER_CSRF);
  if (!fromCookie || !fromHeader) {
    // DEV DIAGNOSTIC: log missing pieces for deterministic debugging
    try {
        if (process.env.NODE_ENV !== 'production') {
          const rawCookieHeader = req.get('cookie');
          const incomingCsrfHeader = req.get(HEADER_CSRF);
          try { (req as any).log?.info?.({ cookieHeader: rawCookieHeader, parsedCookies: req.cookies, xCsrfHeader: incomingCsrfHeader }, DIAG_VALIDATE_CSRF_MISSING); } catch {}

        console.log(DIAG_VALIDATE_CSRF_MISSING, 'cookieHeader=', rawCookieHeader, 'parsedCookies=', JSON.stringify(req.cookies || {}), HEADER_CSRF + '=', incomingCsrfHeader);
      }
    } catch {}
    res.status(403).json({ error: 'CSRF token missing' });
    return;
  }
  const [token, sig] = String(fromCookie).split('.');
  const secret = process.env.CSRF_SECRET || 'dev-csrf-secret';
  const expected = crypto.createHmac('sha256', secret).update(token).digest('hex');
  if (sig !== expected || fromHeader !== fromCookie) {
    // DEV DIAGNOSTIC: log mismatch details so we can correlate header vs cookie seen by server
    try {
        if (process.env.NODE_ENV !== 'production') {
          const rawCookieHeader = req.get('cookie');
          const incomingCsrfHeader = req.get(HEADER_CSRF);
          try { (req as any).log?.info?.({ cookieHeader: rawCookieHeader, parsedCookies: req.cookies, xCsrfHeader: incomingCsrfHeader, expected, sig }, 'diagnostic /validateCsrf mismatch'); } catch {}

        console.log('[diagnostic] /validateCsrf mismatch - cookieHeader=', rawCookieHeader, 'parsedCookies=', JSON.stringify(req.cookies || {}), HEADER_CSRF + '=', incomingCsrfHeader, 'expectedSig=', expected, 'sig=', sig);
      }
    } catch {}
    res.status(403).json({ error: 'CSRF token invalid' });
    return;
  }
  next();
}

// Helpers
function cookieBase() {
  const cookieSecure = typeof process.env.COOKIE_SECURE !== 'undefined'
    ? String(process.env.COOKIE_SECURE) === 'true'
    : (process.env.NODE_ENV === 'production' && String(process.env.APP_ORIGIN || '').startsWith('https'));
  return {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: 'lax' as const,
    path: '/',
  };
}

function signAccessToken(userId: string) {
  const secret: Secret = (process.env.JWT_ACCESS_SECRET || 'dev-access-secret') as Secret;
  const payload = { sub: userId, typ: 'access' } as Record<string, any>;
  const expiresIn = (process.env.ACCESS_TTL ?? '15m') as unknown as SignOptions['expiresIn'];
  const opts: SignOptions = { expiresIn };
  return jwt.sign(payload, secret, opts);
}

function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

async function createRefreshToken(req: Request, userId: string): Promise<{ token: string; expiresAt: Date; maxAgeMs: number }>
{
  const svc = resolveAuthService(req) || null;
  const token = crypto.randomBytes(32).toString('hex');
  // Prefer settings.security.sessionMaxAgeMin, fallback to env REFRESH_DAYS (days)
  let expiresAt: Date;
  let maxAgeMs: number;
  try {
  const s = await prisma.setting.findUnique({ where: { category_key: { category: 'security', key: 'sessionMaxAgeMin' } } });
    const minutes = Number(s?.value ?? 0);
    if (Number.isFinite(minutes) && minutes > 0) {
      maxAgeMs = minutes * 60 * 1000;
      expiresAt = new Date(Date.now() + maxAgeMs);
    } else {
      const days = Number(process.env.REFRESH_DAYS || 30);
      maxAgeMs = days * 24 * 60 * 60 * 1000;
      expiresAt = new Date(Date.now() + maxAgeMs);
    }
  } catch {
    const days = Number(process.env.REFRESH_DAYS || 30);
    maxAgeMs = days * 24 * 60 * 60 * 1000;
    expiresAt = new Date(Date.now() + maxAgeMs);
  }
  const userAgent = req.get(HEADER_UA) || undefined;
  const ipAddress = req.ip;
  await (svc ? svc.createRefreshToken(userId, token, expiresAt, userAgent, ipAddress) : prisma.refreshToken.create({
    data: {
      userId,
      token,
      expiresAt,
      userAgent,
      ipAddress,
    },
  }));
  return { token, expiresAt, maxAgeMs };
}

function setAuthCookies(res: Response, accessToken: string, refreshToken: string, refreshMaxAgeMs?: number): void {
  // access cookie: short TTL via JWT exp; no maxAge needed
  res.cookie('accessToken', accessToken, cookieBase());
  // refresh cookie: explicitly set maxAge
  const maxAge = typeof refreshMaxAgeMs === 'number' && refreshMaxAgeMs > 0
    ? refreshMaxAgeMs
    : Number(process.env.REFRESH_DAYS || 30) * 24 * 60 * 60 * 1000;
  res.cookie('refreshToken', refreshToken, { ...cookieBase(), maxAge });
}

function clearAuthCookies(res: Response): void {
  // Clear both cookies by setting Max-Age=0
  const base = cookieBase();
  res.cookie('accessToken', '', { ...base, maxAge: 0 });
  res.cookie('refreshToken', '', { ...base, maxAge: 0 });
}

async function logAudit(
  userId: string | null,
  action: string,
  req: { ip?: string; get: (name: string) => string | undefined },
  metadata?: any,
) {
  try {
    await prisma.auditLog.create({
      data: {
        userId: userId || undefined,
        action,
        ipAddress: req.ip,
        userAgent: req.get(HEADER_UA) || undefined,
        metadata,
      },
    });
  } catch {
    // best-effort; do not block auth flow on audit failure
  }
}

async function revokeAllRefreshTokens(userId: string) {
  try {
    await prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
  } catch {
    // ignore
  }
}

function sanitizeEmail(value: string): string {
  return String(value ?? '').trim().toLowerCase();
}

function isLegacyBcryptHash(value: unknown): value is string {
  return typeof value === 'string' && LEGACY_BCRYPT_REGEX.test(value);
}

function buildDeviceContext(
  req: Request,
  payload?: Partial<LoginRequestBody | MfaVerifyBody>,
  fallback?: DeviceContext,
): DeviceContext {
  const fingerprintCandidates = [
    payload?.deviceFingerprint,
    req.get(HEADER_DEVICE_FP) ?? undefined,
    fallback?.fingerprint ?? undefined,
  ].map(v => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  const labelCandidates = [payload?.deviceName, fallback?.label].map(v => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  const platformCandidates = [payload?.devicePlatform, fallback?.platform].map(v => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  const pushTokenCandidates = [payload?.devicePushToken, fallback?.pushToken].map(v => (typeof v === 'string' ? v.trim() : '')).filter(Boolean);
  const trustRequested = typeof payload?.trustThisDevice === 'boolean'
    ? payload.trustThisDevice
    : Boolean(fallback?.trustRequested);

  return {
    fingerprint: fingerprintCandidates[0] ?? null,
    label: labelCandidates[0] ?? (fallback?.label ?? (req.get(HEADER_UA) ? 'Browser session' : null)),
    platform: platformCandidates[0] ?? fallback?.platform ?? null,
    userAgent: req.get(HEADER_UA) || fallback?.userAgent || null,
    ipAddress: req.ip || fallback?.ipAddress || null,
    pushToken: pushTokenCandidates[0] ?? fallback?.pushToken ?? null,
    trustRequested,
    trusted: fallback?.trusted,
  } satisfies DeviceContext;
}

function mapFactorType(type: string): ChallengeFactorType {
  switch (type) {
    case 'SMS': return 'sms';
    case 'PUSH': return 'push';
    case 'HARDWARE_KEY': return 'hardware_key';
    case 'BACKUP_CODES': return 'backup_codes';
    default: return 'totp';
  }
}

function mapDbFactorToChallenge(factor: UserMfaFactor): LoginChallengeFactor {
  return {
    id: factor.id,
    type: mapFactorType(factor.type),
    label: factor.label ?? (factor.type === 'TOTP' ? 'Authenticator app' : factor.type),
    lastUsedAt: factor.lastUsedAt?.toISOString() ?? null,
  } satisfies LoginChallengeFactor;
}

function buildChallengePayload(
  data: {
    id: string;
    expiresAt: Date;
    reason: 'mfa_required' | 'untrusted_device';
    device: DeviceContext;
    factors: LoginChallengeFactor[];
    defaultFactorId: string | null;
  },
): LoginChallengePayload {
  return {
    id: data.id,
    expiresAt: data.expiresAt.toISOString(),
    reason: data.reason,
    factors: data.factors,
    defaultFactorId: data.defaultFactorId,
    device: {
      fingerprint: data.device.fingerprint ?? null,
      label: data.device.label ?? null,
      platform: data.device.platform ?? null,
      trustRequested: Boolean(data.device.trustRequested && data.device.fingerprint),
      trusted: Boolean(data.device.trusted),
      allowTrust: Boolean(data.device.fingerprint),
    },
  } satisfies LoginChallengePayload;
}

async function issueMfaChallenge(options: {
  user: User;
  emailKey: string;
  device: DeviceContext;
  factors: UserMfaFactor[];
  reason: 'mfa_required' | 'untrusted_device';
  lockWindowMs: number;
  ipAddress?: string | null;
  userAgent?: string | null;
}): Promise<LoginChallengePayload> {
  const factors = options.factors.map(mapDbFactorToChallenge);
  const defaultFactorId = factors.find(f => f.type !== 'backup_codes')?.id ?? factors[0]?.id ?? null;
  const token = generateToken();
  const expiresAt = new Date(Date.now() + MFA_CHALLENGE_TTL_MS);

  const metadata: ChallengeMetadata = {
    version: 1,
    userId: options.user.id,
    email: options.emailKey,
    loginAt: new Date().toISOString(),
    ipAddress: options.ipAddress ?? null,
    userAgent: options.userAgent ?? null,
    device: options.device,
    rateLimit: { scope: 'auth_login_user_fail', key: options.emailKey, windowMs: options.lockWindowMs },
    factors,
    defaultFactorId,
  } satisfies ChallengeMetadata;

  await prisma.verificationToken.create({
    data: {
      identifier: options.user.id,
      token,
      type: 'mfa_challenge',
      expiresAt,
      metadata: metadata as Prisma.InputJsonValue,
    },
  });

  return buildChallengePayload({ id: token, expiresAt, reason: options.reason, device: options.device, factors, defaultFactorId });
}

function parseChallengeMetadata(value: unknown): ChallengeMetadata | null {
  if (!value || typeof value !== 'object') return null;
  try {
    const record = value as Record<string, any>;
    if (!record.userId || !record.email || !Array.isArray(record.factors)) return null;
    const metadata: ChallengeMetadata = {
      version: Number(record.version ?? 1),
      userId: String(record.userId),
      email: String(record.email),
      loginAt: String(record.loginAt ?? new Date().toISOString()),
      ipAddress: record.ipAddress ? String(record.ipAddress) : null,
      userAgent: record.userAgent ? String(record.userAgent) : null,
      device: record.device as DeviceContext | undefined,
      rateLimit: record.rateLimit as ChallengeMetadata['rateLimit'],
      factors: Array.isArray(record.factors) ? record.factors as LoginChallengeFactor[] : [],
      defaultFactorId: record.defaultFactorId ? String(record.defaultFactorId) : null,
    };
    return metadata;
  } catch {
    return null;
  }
}

function normalizeBackupCodeInput(input: string): string {
  const raw = String(input ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (!raw) return '';
  if (raw.length === 10) {
    return `${raw.slice(0, 5)}-${raw.slice(5)}`;
  }
  return raw;
}

function hashBackupCodeValue(code: string): string {
  return crypto.createHash('sha256').update(code).digest('hex');
}

async function findMatchingBackupCode(userId: string, code: string): Promise<UserBackupCode | null> {
  const normalized = normalizeBackupCodeInput(code);
  if (!normalized) return null;
  const shaHash = hashBackupCodeValue(normalized);
  const db = prisma as any;
  const direct = await (db.userBackupCode.findFirst({ where: { userId, codeHash: shaHash, usedAt: null } }) as Promise<UserBackupCode | null>);
  if (direct) return direct;
  const candidates = await (db.userBackupCode.findMany({ where: { userId, usedAt: null }, take: 25 }) as Promise<UserBackupCode[]>);
  for (const entry of candidates) {
    const matches = await argon2.verify(entry.codeHash, normalized).catch(() => false);
    if (matches) {
      return entry;
    }
  }
  return null;
}

async function markBackupCodeUsed(entry: UserBackupCode): Promise<void> {
  const db = prisma as any;
  await db.userBackupCode.update({ where: { id: entry.id }, data: { usedAt: new Date() } }).catch(() => {});
}

async function resetLoginFailureWindow(rateSvc: RateLimitService | null, emailKey: string, windowMs: number): Promise<void> {
  if (!emailKey) return;
  if (!rateSvc) {
    await libResetWindow('auth_login_user_fail', emailKey, windowMs);
    return;
  }
  try {
    await rateSvc.resetWindow('auth_login_user_fail', emailKey, windowMs);
  } catch (err) {
    try { (global as any)?.console?.warn?.('rateLimit.resetWindow failed, falling back', err); } catch {}
    await libResetWindow('auth_login_user_fail', emailKey, windowMs);
  }
}

async function incrementChallengeFailureRate(
  rateSvc: RateLimitService | null,
  rateLimit?: ChallengeMetadata['rateLimit'] | null,
): Promise<void> {
  if (!rateLimit?.scope || !rateLimit?.key) return;
  const payload = {
    scope: rateLimit.scope,
    key: rateLimit.key,
    windowMs: typeof rateLimit.windowMs === 'number' && rateLimit.windowMs > 0 ? rateLimit.windowMs : 15 * 60 * 1000,
    limit: Number.MAX_SAFE_INTEGER,
  };
  if (!rateSvc) {
    await libIncrementAndCheck(payload);
    return;
  }
  try {
    await rateSvc.incrementAndCheck(payload);
  } catch (err) {
    try { (global as any)?.console?.warn?.({ err }, WARN_RATE_LIMIT_INCREMENT); } catch {}
    await libIncrementAndCheck(payload);
  }
}

async function consumeVerificationToken(tokenId: string): Promise<void> {
  try {
    await prisma.verificationToken.delete({ where: { id: tokenId } });
    return;
  } catch {}
  try {
    await prisma.verificationToken.update({ where: { id: tokenId }, data: { consumedAt: new Date() } });
  } catch {
    // ignore consumption failure
  }
}

async function recordDeviceSession(options: {
  userId: string;
  refreshTokenValue: string;
  context: DeviceContext;
  trustSource?: string;
}): Promise<UserDevice | null> {
  const { context } = options;
  if (!context.fingerprint && !context.userAgent && !context.label) {
    return null;
  }
  const now = new Date();
  const baseData = {
    userId: options.userId,
    fingerprint: context.fingerprint ?? undefined,
    label: context.label ?? 'Browser session',
    platform: context.platform ?? null,
    userAgent: context.userAgent ?? null,
    ipAddress: context.ipAddress ?? null,
    pushToken: context.pushToken ?? null,
    lastSeenAt: now,
    trustedAt: context.trustRequested && context.fingerprint ? now : null,
    trustSource: context.trustRequested && context.fingerprint ? (options.trustSource ?? 'login') : undefined,
    status: 'active',
  } as Record<string, unknown>;

  let device: UserDevice | null = null;
  const db = prisma as any;
  if (context.fingerprint) {
    device = await db.userDevice.upsert({
      where: { userId_fingerprint: { userId: options.userId, fingerprint: context.fingerprint } } as any,
      update: {
        label: baseData.label,
        platform: baseData.platform,
        userAgent: baseData.userAgent,
        ipAddress: baseData.ipAddress,
        pushToken: baseData.pushToken,
        lastSeenAt: baseData.lastSeenAt,
        trustedAt: context.trustRequested ? now : undefined,
        trustSource: context.trustRequested ? (options.trustSource ?? 'login') : undefined,
        status: 'active',
      },
      create: baseData,
    });
  } else {
    device = await db.userDevice.create({ data: baseData }).catch(() => null);
  }

  if (device?.id) {
    await prisma.refreshToken.update({ where: { token: options.refreshTokenValue }, data: { deviceId: device.id } as any }).catch(() => {});
  }

  return device;
}

// Register: email/password
router.post('/register', validateCsrf, async (req: Request, res: Response) => {
  try {
    const { email, password, name } = (req.body || {}) as { email?: string; password?: string; name?: string };
    if (!email || !password || !name) return res.status(400).json({ error: 'name, email and password are required' });
    if (!meetsRegistrationPasswordRequirements(password)) {
      return res.status(400).json({ error: 'password does not meet complexity requirements' });
    }
  const authSvc = resolveAuthService(req);
  const existing = authSvc ? await authSvc.findUserByEmail(email) : await prisma.user.findUnique({ where: { email } });
  if (existing) return res.status(409).json({ error: 'account already exists' });
    const hashOpts = process.env.NODE_ENV === 'test'
      ? { type: argon2.argon2id, timeCost: 2, memoryCost: 1024, parallelism: 1 }
      : { type: argon2.argon2id };
  const passwordHash = await argon2.hash(password, hashOpts);
  const createPayload: Prisma.UserCreateInput | Prisma.UserUncheckedCreateInput = { email, passwordHash, name, lastLoginAt: new Date() };
  const user = authSvc ? await authSvc.createUser(createPayload) : await prisma.user.create({ data: createPayload });
  await logAudit(String(user.id), 'auth.register', { ip: req.ip, get: req.get.bind(req) });
    const access = signAccessToken(String(user.id));
  const rt = await createRefreshToken(req, String(user.id));
    setAuthCookies(res, access, rt.token, rt.maxAgeMs);
    return res.status(201).json({ id: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified, lastLoginAt: user.lastLoginAt });
  } catch (err: any) {
    // Log detailed error but avoid leaking internals in production
    try {
      (req as any).log?.error({ err }, 'register failed');
    } catch {
      // no-op
    }
    const message = process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

// Login: email/password
router.post('/login', validateCsrf, async (req: Request, res: Response) => {
  try {
    const parsed = LoginRequestSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parsed.error.flatten() });
    }
    const { email, password } = parsed.data;
    if (!email?.trim() || !password?.trim()) {
      return res.status(400).json({ error: 'email and password are required' });
    }
    const emailKey = sanitizeEmail(email);
    const deviceContext = buildDeviceContext(req, parsed.data);
    const now = new Date();
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      const activeLock = await prisma.userLock.findFirst({
        where: { userId: existingUser.id, unlockedAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
        orderBy: { lockedAt: 'desc' },
      });
      if (activeLock) {
        return res.status(429).json({ error: 'account locked', reason: activeLock.reason, until: activeLock.expiresAt ?? null });
      }
      const expired = await prisma.userLock.findMany({ where: { userId: existingUser.id, unlockedAt: null, expiresAt: { lte: now } } });
      if (expired.length) {
        await prisma.userLock.updateMany({ where: { userId: existingUser.id, unlockedAt: null, expiresAt: { lte: now } }, data: { unlockedAt: now } });
      }
    }

    const ip = req.ip || (req.headers['x-forwarded-for'] as string) || 'unknown';
    const ua = req.get(HEADER_UA) || undefined;

    let ipWindowMs = Number(process.env.LOGIN_IP_WINDOW_MS || 60_000);
    let ipLimit = Number(process.env.LOGIN_IP_LIMIT || 20);
    let lockWindowMs = Number(process.env.LOGIN_LOCK_WINDOW_MS || 15 * 60_000);
    let lockThreshold = Number(process.env.LOGIN_LOCK_THRESHOLD || 5);
    try {
      const rows = await prisma.setting.findMany({ where: { category: 'security', key: { in: ['loginIpWindowSec', 'loginIpLimit', 'loginLockWindowSec', 'loginLockThreshold'] } } });
      const map = new Map(rows.map((r: any) => [r.key, r.value]));
      const ipWinSec = Number(map.get('loginIpWindowSec'));
      const ipLim = Number(map.get('loginIpLimit'));
      const lockWinSec = Number(map.get('loginLockWindowSec'));
      const lockThr = Number(map.get('loginLockThreshold'));
      if (Number.isFinite(ipWinSec) && ipWinSec > 0) ipWindowMs = ipWinSec * 1000;
      if (Number.isFinite(ipLim) && ipLim > 0) ipLimit = ipLim;
      if (Number.isFinite(lockWinSec) && lockWinSec > 0) lockWindowMs = lockWinSec * 1000;
      if (Number.isFinite(lockThr) && lockThr > 0) lockThreshold = lockThr;
    } catch {}

    const rateSvc = resolveRateLimitService(req);
    let ipCheck;
    if (!rateSvc) {
      ipCheck = await libIncrementAndCheck({ scope: 'auth_login_ip', key: String(ip), windowMs: ipWindowMs, limit: ipLimit });
    } else {
      try {
        ipCheck = await rateSvc.incrementAndCheck({ scope: 'auth_login_ip', key: String(ip), windowMs: ipWindowMs, limit: ipLimit });
      } catch (err) {
  try { (req as any).log?.warn?.({ err }, WARN_RATE_LIMIT_INCREMENT); } catch {}
        ipCheck = await libIncrementAndCheck({ scope: 'auth_login_ip', key: String(ip), windowMs: ipWindowMs, limit: ipLimit });
      }
    }
    if (!ipCheck.allowed) {
      await logAudit(null, 'auth.login.throttled_ip', { ip: req.ip, get: req.get.bind(req) }, { ip, ua });
      return res.status(429).json({ error: 'too many attempts, try again later' });
    }

    let userFail;
    if (!rateSvc) {
      userFail = await libGetCount({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs });
    } else {
      try {
        userFail = await rateSvc.getCount({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs });
      } catch (err) {
  try { (req as any).log?.warn?.({ err }, 'rateLimit.getCount failed, falling back'); } catch {}
        userFail = await libGetCount({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs });
      }
    }
    if (userFail.count >= lockThreshold) {
      await logAudit(null, AUDIT_LOGIN_LOCKED, { ip: req.ip, get: req.get.bind(req) }, { email });
      return res.status(429).json({ error: 'account temporarily locked due to failed attempts' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) {
      if (!rateSvc) {
        await libIncrementAndCheck({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs, limit: Number.MAX_SAFE_INTEGER });
      } else {
        try {
          await rateSvc.incrementAndCheck({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs, limit: Number.MAX_SAFE_INTEGER });
        } catch (err) {
          try { (req as any).log?.warn?.({ err }, WARN_RATE_LIMIT_INCREMENT); } catch {}
          await libIncrementAndCheck({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs, limit: Number.MAX_SAFE_INTEGER });
        }
      }
      return res.status(401).json({ error: 'invalid credentials' });
    }

    try {
      const setting = await prisma.setting.findUnique({ where: { category_key: { category: 'security', key: 'requireEmailVerification' } } });
      const required = Boolean(setting?.value ?? true);
      if (required && !user.emailVerified) return res.status(403).json({ error: 'email verification required' });
    } catch {}

    const legacyHash = isLegacyBcryptHash(user.passwordHash);
    let ok = false;
    if (legacyHash) {
      try {
        ok = await bcrypt.compare(password, String(user.passwordHash));
      } catch (err) {
        try { (req as any).log?.warn?.({ err }, 'legacy bcrypt verify failed'); } catch {}
        ok = false;
      }
    } else {
      try {
        ok = await argon2.verify(String(user.passwordHash), password);
      } catch (err) {
        try { (req as any).log?.warn?.({ err }, 'argon verify failed'); } catch {}
        ok = false;
      }
    }

    if (ok && legacyHash) {
      try {
        const hashOpts = process.env.NODE_ENV === 'test'
          ? { type: argon2.argon2id, timeCost: 2, memoryCost: 1024, parallelism: 1 }
          : { type: argon2.argon2id };
        const upgradedHash = await argon2.hash(password, hashOpts);
        await prisma.user.update({ where: { id: user.id }, data: { passwordHash: upgradedHash } });
      } catch (err) {
        try { (req as any).log?.warn?.({ err }, 'password hash upgrade failed'); } catch {}
      }
    }

    if (!ok) {
      if (!rateSvc) {
        await libIncrementAndCheck({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs, limit: Number.MAX_SAFE_INTEGER });
      } else {
        try {
          await rateSvc.incrementAndCheck({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs, limit: Number.MAX_SAFE_INTEGER });
        } catch (err) {
    try { (req as any).log?.warn?.({ err }, WARN_RATE_LIMIT_INCREMENT); } catch {}
          await libIncrementAndCheck({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs, limit: Number.MAX_SAFE_INTEGER });
        }
      }
      let after;
      if (!rateSvc) {
        after = await libGetCount({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs });
      } else {
        try {
          after = await rateSvc.getCount({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs });
        } catch (err) {
    try { (req as any).log?.warn?.({ err }, 'rateLimit.getCount failed, falling back'); } catch {}
          after = await libGetCount({ scope: 'auth_login_user_fail', key: emailKey, windowMs: lockWindowMs });
        }
      }
      if (after.count >= lockThreshold) {
        await logAudit(user.id, AUDIT_LOGIN_LOCKED, { ip: req.ip, get: req.get.bind(req) }, { email });
        let durationMs = Number(process.env.LOGIN_LOCK_DURATION_MS || 15 * 60_000);
        try {
          const s = await prisma.setting.findUnique({ where: { category_key: { category: 'security', key: 'loginLockDurationMin' } } });
          const min = Number(s?.value);
          if (Number.isFinite(min) && min > 0) durationMs = min * 60_000;
        } catch {}
        await prisma.userLock.create({ data: { userId: user.id, reason: 'auto_failed_logins', manual: false, lockedAt: new Date(), expiresAt: new Date(Date.now() + durationMs) } });
        return res.status(429).json({ error: 'account temporarily locked due to failed attempts' });
      }
      return res.status(401).json({ error: 'invalid credentials' });
    }

    const activeFactors = await prisma.userMfaFactor.findMany({ where: { userId: user.id, enabled: true } });
    const hasMfa = activeFactors.length > 0;
    let deviceTrusted = false;
    if (deviceContext.fingerprint) {
      const db = prisma as any;
      const knownDevice = await (db.userDevice.findFirst({ where: { userId: user.id, fingerprint: deviceContext.fingerprint } }) as Promise<UserDevice | null>);
      if (knownDevice?.trustedAt) {
        deviceTrusted = true;
        deviceContext.trusted = true;
      }
    }
    if (hasMfa && !deviceTrusted) {
      const challenge = await issueMfaChallenge({
        user,
        emailKey,
        device: deviceContext,
        factors: activeFactors,
        reason: 'mfa_required',
        lockWindowMs,
        ipAddress: req.ip ?? null,
        userAgent: ua ?? null,
      });
      await logAudit(user.id, 'auth.login.mfa_challenge', { ip: req.ip, get: req.get.bind(req) }, { deviceFingerprint: deviceContext.fingerprint ?? null });
      return res.status(202).json({ challengeRequired: true, challenge });
    }

    const loginAt = new Date();
    await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: loginAt } }).catch(() => {});
    await logAudit(user.id, 'auth.login', { ip: req.ip, get: req.get.bind(req) });
    await resetLoginFailureWindow(rateSvc ?? null, emailKey, lockWindowMs);

    const access = signAccessToken(user.id);
    const rt = await createRefreshToken(req, user.id);
    const trustContext = { ...deviceContext, trustRequested: Boolean(deviceContext.trustRequested && deviceContext.fingerprint) };
    await recordDeviceSession({ userId: user.id, refreshTokenValue: rt.token, context: trustContext });
    setAuthCookies(res, access, rt.token, rt.maxAgeMs);
    return res.json({ id: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified, lastLoginAt: loginAt });
  } catch (err: any) {
    try {
      (req as any).log?.error({ err }, 'login failed');
    } catch {}
    const message = process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/mfa/verify', validateCsrf, async (req: Request, res: Response) => {
  try {
    const parsed = MfaVerifySchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parsed.error.flatten() });
    }
    const payload = parsed.data;
    const challenge = await prisma.verificationToken.findUnique({ where: { token: payload.challengeId } });
    if (!challenge || challenge.type !== 'mfa_challenge') {
      return res.status(404).json({ error: 'challenge not found' });
    }
    if (challenge.consumedAt || challenge.expiresAt <= new Date()) {
      await consumeVerificationToken(challenge.id);
      return res.status(410).json({ error: 'challenge expired' });
    }
    const metadata = parseChallengeMetadata(challenge.metadata);
    if (!metadata) {
      await consumeVerificationToken(challenge.id);
      return res.status(400).json({ error: 'challenge metadata invalid' });
    }
    const user = await prisma.user.findUnique({ where: { id: metadata.userId } });
    if (!user) {
      await consumeVerificationToken(challenge.id);
      return res.status(404).json({ error: ERROR_USER_NOT_FOUND });
    }

    const rateSvc = resolveRateLimitService(req);
    const rateInfo = metadata.rateLimit ?? null;
    const method = payload.method ?? (payload.backupCode ? 'backup_code' : 'totp');
    const db = prisma as any;
    let factorUsed: UserMfaFactor | null = null;

    if (method === 'backup_code') {
      if (!payload.backupCode) {
        return res.status(400).json({ error: 'backup code required' });
      }
      const backupEntry = await findMatchingBackupCode(user.id, payload.backupCode);
      if (!backupEntry) {
        await incrementChallengeFailureRate(rateSvc, rateInfo);
        await logAudit(user.id, 'auth.login.mfa_backup_code_invalid', { ip: req.ip, get: req.get.bind(req) }, { challengeId: payload.challengeId });
        return res.status(401).json({ error: 'invalid or used backup code' });
      }
      await markBackupCodeUsed(backupEntry);
      if (backupEntry.factorId) {
        factorUsed = await (db.userMfaFactor.findFirst({ where: { id: backupEntry.factorId } }) as Promise<UserMfaFactor | null>);
      }
    } else {
      if (!payload.code) {
        return res.status(400).json({ error: 'code required' });
      }
      const targetFactorId = payload.factorId ?? metadata.defaultFactorId ?? metadata.factors[0]?.id ?? null;
      if (!targetFactorId) {
        return res.status(400).json({ error: 'factor required' });
      }
      factorUsed = await (db.userMfaFactor.findFirst({ where: { id: targetFactorId, userId: user.id, enabled: true } }) as Promise<UserMfaFactor | null>);
      if (!factorUsed || !factorUsed.secret) {
        await incrementChallengeFailureRate(rateSvc, rateInfo);
        return res.status(404).json({ error: 'factor not found' });
      }
      let totpValid = false;
      try {
        totpValid = verifyTotpCode(factorUsed.secret, payload.code);
      } catch {
        totpValid = false;
      }
      if (!totpValid) {
        await incrementChallengeFailureRate(rateSvc, rateInfo);
        await logAudit(user.id, 'auth.login.mfa_code_invalid', { ip: req.ip, get: req.get.bind(req) }, { factorId: factorUsed.id });
        return res.status(401).json({ error: 'invalid code' });
      }
      await db.userMfaFactor.update({ where: { id: factorUsed.id }, data: { lastUsedAt: new Date() } }).catch(() => {});
    }

    await consumeVerificationToken(challenge.id);
    if (rateInfo?.key && rateInfo?.windowMs) {
      await resetLoginFailureWindow(rateSvc ?? null, rateInfo.key, rateInfo.windowMs);
    }

    const loginAt = new Date();
    await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: loginAt } }).catch(() => {});
    const deviceContext = buildDeviceContext(req, payload, metadata.device);
    deviceContext.trustRequested = Boolean((typeof payload.trustThisDevice === 'boolean' ? payload.trustThisDevice : metadata.device?.trustRequested) && deviceContext.fingerprint);

    const access = signAccessToken(user.id);
    const rt = await createRefreshToken(req, user.id);
    await recordDeviceSession({ userId: user.id, refreshTokenValue: rt.token, context: deviceContext, trustSource: 'mfa_verify' });

    setAuthCookies(res, access, rt.token, rt.maxAgeMs);
    await logAudit(user.id, 'auth.login.mfa_verified', { ip: req.ip, get: req.get.bind(req) }, { challengeId: payload.challengeId, factorId: factorUsed?.id ?? null, method });

    return res.json({ id: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified, lastLoginAt: loginAt });
  } catch (err: any) {
    try {
      (req as any).log?.error({ err }, 'mfa verify failed');
    } catch {}
    const message = process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/logout', validateCsrf, async (req: Request, res: Response) => {
  try {
    const rt = req.cookies?.refreshToken as string | undefined;
    if (rt) {
      try {
        const authSvcLogout = resolveAuthService(req);
        const existing = authSvcLogout ? await authSvcLogout.findRefreshToken(rt) : await prisma.refreshToken.findUnique({ where: { token: rt } });
        if (existing && !existing.revokedAt) {
          if (authSvcLogout) await authSvcLogout.revokeRefreshToken(rt);
          else await prisma.refreshToken.update({ where: { token: rt }, data: { revokedAt: new Date() } });
        await logAudit(String(existing.userId), 'auth.logout', { ip: req.ip, get: req.get.bind(req) }, { reason: 'user initiated' });
        }
      } catch {
        // ignore revocation errors on logout
      }
    }
    clearAuthCookies(res);
    return res.status(204).send();
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'logout failed'); } catch {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

router.post('/refresh', validateCsrf, async (req: Request, res: Response) => {
  try {
    // TEMP DIAGNOSTIC: log incoming Cookie header and parsed cookies for deterministic debugging in dev
    try {
      if (process.env.NODE_ENV !== 'production') {
        const rawCookieHeader = req.get('cookie');
        const incomingCsrfHeader = req.get('x-csrf-token');
        // Use console.log to ensure visible in local dev environment; also use structured logger if available
        try { (req as any).log?.info?.({ cookieHeader: rawCookieHeader, parsedCookies: req.cookies, xCsrfHeader: incomingCsrfHeader }, 'diagnostic /auth/refresh incoming'); } catch {}

        console.log('[diagnostic] /auth/refresh incoming - cookieHeader=', rawCookieHeader, 'parsedCookies=', JSON.stringify(req.cookies || {}), 'x-csrf-token=', incomingCsrfHeader);
      }
      } catch {
        // swallow diagnostics errors
      }
    const rt = req.cookies?.refreshToken as string | undefined;
    if (!rt) return res.status(401).json({ error: 'missing refresh token' });
    const authSvcRefresh = resolveAuthService(req);
    const existing = authSvcRefresh ? await authSvcRefresh.findRefreshToken(rt) : await prisma.refreshToken.findUnique({ where: { token: rt } });
    if (!existing) return res.status(401).json({ error: 'invalid refresh token' });
    if (existing.revokedAt) return res.status(401).json({ error: 'refresh token revoked' });
    if (existing.expiresAt <= new Date()) return res.status(401).json({ error: 'refresh token expired' });

    // rotate
  const created = await createRefreshToken(req, String(existing.userId));
    if (authSvcRefresh) {
      await authSvcRefresh.revokeRefreshToken(rt);
      await authSvcRefresh.prisma.refreshToken.update({ where: { token: rt }, data: { revokedAt: new Date(), replacedByToken: created.token } });
    } else {
      await prisma.refreshToken.update({ where: { token: rt }, data: { revokedAt: new Date(), replacedByToken: created.token } });
    }

  const access = signAccessToken(String(existing.userId));
    setAuthCookies(res, access, created.token, created.maxAgeMs);
    await logAudit(String(existing.userId), 'auth.refresh', { ip: req.ip, get: req.get.bind(req) }, { rotatedFrom: rt });
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'refresh failed'); } catch {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

router.post('/request-email-verification', validateCsrf, async (req: Request, res: Response) => {
  try {
    const { email } = (req.body || {}) as { email?: string };
    if (!email) return res.status(400).json({ error: 'email is required' });
    const user = await prisma.user.findUnique({ where: { email } });
    // Always respond 200 to avoid enumeration
    if (!user) return res.json({ ok: true });
    if (user.emailVerified) return res.json({ ok: true });
    const token = generateToken();
    const ttlMin = Number(process.env.EMAIL_VERIFICATION_TTL_MIN || 60 * 24); // default 24h
    const expiresAt = new Date(Date.now() + ttlMin * 60 * 1000);
    const authSvc2 = resolveAuthService(req);
    if (authSvc2) await authSvc2.createVerificationToken(email, token, 'email_verify', expiresAt);
    else await prisma.verificationToken.create({ data: { identifier: email, token, type: 'email_verify', expiresAt } });
  await logAudit(user.id, 'auth.email_verification.request', { ip: req.ip, get: req.get.bind(req) });
    try {
      const appOrigin = process.env.APP_ORIGIN || 'http://localhost:5173';
      const verifyUrl = `${appOrigin}/verify-email?token=${encodeURIComponent(token)}`;
      const tpl = verificationEmailTemplate({ verifyUrl });
      await sendMail({ to: email, subject: 'Verify your email', text: tpl.text, html: tpl.html });
      (req as any).log?.info({ email }, 'verification email sent');
    } catch (e) {
      // log and continue; avoid leaking internals
      try { (req as any).log?.error({ e }, 'failed to send verification email'); } catch {}
    }
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'request-email-verification failed'); } catch {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

router.post('/verify-email', validateCsrf, async (req: Request, res: Response) => {
  try {
    const { token } = (req.body || {}) as { token?: string };
    if (!token) return res.status(400).json({ error: 'token is required' });
    const authSvc3 = resolveAuthService(req);
    const vt = authSvc3 ? await authSvc3.findVerificationToken(token) : await prisma.verificationToken.findUnique({ where: { token } });
  if (!vt || vt.type !== 'email_verify') return res.status(400).json({ error: INVALID_TOKEN });
    if (vt.consumedAt) return res.status(400).json({ error: 'token already used' });
    if (vt.expiresAt <= new Date()) return res.status(400).json({ error: 'token expired' });
    const user = authSvc3 ? await authSvc3.findUserByEmail(vt.identifier) : await prisma.user.findUnique({ where: { email: vt.identifier } });
  if (!user) return res.status(400).json({ error: INVALID_TOKEN });
    let updated: any = user;
    if (authSvc3) {
      const updatePayload: Prisma.UserUpdateInput = { emailVerified: new Date() } as Prisma.UserUpdateInput;
      updated = await authSvc3.updateUser(user.id, updatePayload);
      await authSvc3.consumeVerificationToken(vt.id);
      await authSvc3.revokeAllRefreshTokens(user.id);
    } else {
      updated = await prisma.user.update({ where: { id: user.id }, data: { emailVerified: new Date() } });
      await prisma.verificationToken.update({ where: { id: vt.id }, data: { consumedAt: new Date() } });
      await revokeAllRefreshTokens(user.id);
    }
  await logAudit(String(user.id), 'auth.email_verification.verified', { ip: req.ip, get: req.get.bind(req) });
    // issue fresh session
  const access = signAccessToken(user.id);
  const rt = await createRefreshToken(req, String(user.id));
    setAuthCookies(res, access, rt.token, rt.maxAgeMs);
    return res.json({ id: updated.id, email: updated.email, emailVerified: updated.emailVerified });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'verify-email failed'); } catch {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

router.post('/request-password-reset', validateCsrf, async (req: Request, res: Response) => {
  try {
    const { email } = (req.body || {}) as { email?: string };
    if (!email) return res.status(400).json({ error: 'email is required' });
    const user = await prisma.user.findUnique({ where: { email } });
    // Always respond 200 to avoid user enumeration
    if (!user) return res.json({ ok: true });
    const token = generateToken();
    const ttl = Number(process.env.PASSWORD_RESET_TTL_MIN || 60); // minutes
    const expiresAt = new Date(Date.now() + ttl * 60 * 1000);
    const authSvc4 = resolveAuthService(req);
    if (authSvc4) await authSvc4.createVerificationToken(email, token, 'password_reset', expiresAt);
    else await prisma.verificationToken.create({ data: { identifier: email, token, type: 'password_reset', expiresAt } });
  await logAudit(String(user.id), 'auth.password_reset.request', { ip: req.ip, get: req.get.bind(req) });
    try {
      const appOrigin = process.env.APP_ORIGIN || 'http://localhost:5173';
      const resetUrl = `${appOrigin}/reset-password?token=${encodeURIComponent(token)}`;
      const tpl = resetPasswordEmailTemplate({ resetUrl });
      await sendMail({ to: email, subject: 'Reset your password', text: tpl.text, html: tpl.html });
      (req as any).log?.info({ email }, 'password reset email sent');
    } catch (e) {
      try { (req as any).log?.error({ e }, 'failed to send password reset email'); } catch {}
    }
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'request-password-reset failed'); } catch {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

router.post('/reset-password', validateCsrf, async (req: Request, res: Response) => {
  try {
    const { token, password } = (req.body || {}) as { token?: string; password?: string };
    if (!token || !password) return res.status(400).json({ error: 'token and password are required' });
    const authSvc5 = resolveAuthService(req);
    const vt = authSvc5 ? await authSvc5.findVerificationToken(token) : await prisma.verificationToken.findUnique({ where: { token } });
  if (!vt || vt.type !== 'password_reset') return res.status(400).json({ error: INVALID_TOKEN });
    if (vt.consumedAt) return res.status(400).json({ error: 'token already used' });
    if (vt.expiresAt <= new Date()) return res.status(400).json({ error: 'token expired' });
    const user = authSvc5 ? await authSvc5.findUserByEmail(vt.identifier) : await prisma.user.findUnique({ where: { email: vt.identifier } });
  if (!user) return res.status(400).json({ error: INVALID_TOKEN });
    // Enforce password history: not among last N
    // Password history limit (settings override)
    let historyLimit = Number(process.env.PASSWORD_HISTORY_LIMIT || 10);
    try {
  const s = await prisma.setting.findUnique({ where: { category_key: { category: 'security', key: 'passwordHistoryLimit' } } });
      const lim = Number(s?.value);
      if (Number.isFinite(lim) && lim >= 0) historyLimit = lim;
    } catch {}
    if (historyLimit > 0 && user.passwordHash) {
  const history = await prisma.passwordHistory.findMany({ where: { userId: user.id }, orderBy: { createdAt: 'desc' }, take: historyLimit });
      for (const h of history) {
        const match = await argon2.verify(String(h.passwordHash), password).catch(() => false);
        if (match) return res.status(400).json({ error: 'new password must not match any of the last 10 passwords' });
      }
      // Also prevent setting same as current
      const currentMatches = await argon2.verify(user.passwordHash, password).catch(() => false);
      if (currentMatches) return res.status(400).json({ error: 'new password must not match your current password' });
    }
    const hashOpts = process.env.NODE_ENV === 'test'
      ? { type: argon2.argon2id, timeCost: 2, memoryCost: 1024, parallelism: 1 }
      : { type: argon2.argon2id };
  const passwordHash = (await (argon2 as any).hash(password, hashOpts)) as string;
  const updateData: Prisma.UserUpdateInput = { passwordHash };
    // If the account wasn't verified yet, password reset via emailed token proves control of inbox.
    // Mark emailVerified to allow immediate login post-reset.
    if (!user.emailVerified) updateData.emailVerified = new Date();
    // Save previous hash into history if it existed
    if (user.passwordHash) {
  try { if (authSvc5) await authSvc5.prisma.passwordHistory.create({ data: { userId: user.id, passwordHash: user.passwordHash } }); else await prisma.passwordHistory.create({ data: { userId: user.id, passwordHash: user.passwordHash } }); } catch {}
      // Trim to last N
      try {
  const extra = await prisma.passwordHistory.findMany({ where: { userId: user.id }, orderBy: { createdAt: 'desc' }, skip: historyLimit, take: 1000 });
        if (extra.length) {
          const ids: string[] = (extra as Array<{ id: string }>).map(e => String(e.id));
          await prisma.passwordHistory.deleteMany({ where: { id: { in: ids } } });
        }
      } catch {}
    }
    // Persist the password change and mark token consumed. Also revoke previous refresh tokens.
    if (authSvc5) {
      try { await authSvc5.updateUser(user.id, updateData); } catch {}
      try { await authSvc5.consumeVerificationToken(vt.id); } catch {}
      try { await authSvc5.revokeAllRefreshTokens(user.id); } catch {}
    } else {
      try { await prisma.user.update({ where: { id: user.id }, data: updateData }); } catch {}
      try { await prisma.verificationToken.update({ where: { id: vt.id }, data: { consumedAt: new Date() } }); } catch {}
      try { await revokeAllRefreshTokens(user.id); } catch {}
    }

  await logAudit(String(user.id), 'auth.password_reset.reset', { ip: req.ip, get: req.get.bind(req) });
    // issue new session cookies
    const access = signAccessToken(user.id);
    const rt = await createRefreshToken(req, user.id);
    setAuthCookies(res, access, rt.token, rt.maxAgeMs);
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'reset-password failed'); } catch {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

router.get('/me', async (req: any, res: Response) => {
  try {
    const userId = req.user?.id || req.user?.sub;
    if (!userId) return res.status(401).json({ authenticated: false });
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(401).json({ authenticated: false });
    const roles: string[] = Array.isArray(req.user?.roles) ? req.user.roles : [];
    const permissions: string[] = Array.isArray(req.user?.permissions) ? req.user.permissions : [];
  const metadata = parseUserMetadata((user as any).metadata);
    return res.json({
      id: user.id,
      email: user.email,
      name: user.name,
      image: user.image,
      emailVerified: user.emailVerified,
      roles,
      permissions,
      metadata: metadata ?? null,
      lastLoginAt: user.lastLoginAt,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
  } catch (err: any) {
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

router.put('/me', requireAuth as unknown as RequestHandler, validateCsrf, async (req: any, res: Response) => {
  try {
    const userId = req.user?.id || req.user?.sub;
    if (!userId) return res.status(401).json({ error: 'unauthorized' });

    const parsed = UpdateProfileSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.format() });
    }

    const input = parsed.data;
  const existing = await prisma.user.findUnique({ where: { id: userId } });
  if (!existing) return res.status(404).json({ error: ERROR_USER_NOT_FOUND });

  // Use a loose type for update payload so we can conditionally assign JSON/JsonNull
  const updateData: any = {};

    const normalize = (value: string | null | undefined): string | null => {
      if (typeof value !== 'string') return null;
      const trimmed = value.trim();
      return trimmed.length ? trimmed : null;
    };

    if (input.name !== undefined) {
      const normalizedName = normalize(input.name);
      const currentName = typeof existing.name === 'string' ? normalize(existing.name) : null;
      if (normalizedName !== currentName) {
        updateData.name = normalizedName;
      }
    }
    if (input.avatarUrl !== undefined) {
      const normalizedAvatar = normalize(input.avatarUrl);
      const currentImage = typeof existing.image === 'string' ? normalize(existing.image) : null;
      if (normalizedAvatar !== currentImage) {
        updateData.image = normalizedAvatar;
      }
    }

  const metadata = cloneUserMetadata((existing as any).metadata);
    let metadataTouched = false;
    const applyMeta = (key: string, value: string | null | undefined) => {
      if (value === undefined) return;
      const normalized = normalize(value);
      const existingValue = typeof metadata[key] === 'string' ? normalize(String(metadata[key])) : null;
      if (normalized === null) {
        if (existingValue !== null) {
          metadataTouched = true;
          delete metadata[key];
        }
        return;
      }
      if (existingValue === normalized) {
        return;
      }
      metadataTouched = true;
      metadata[key] = normalized;
    };

    applyMeta('avatarUrl', input.avatarUrl);
    applyMeta('title', input.title);
    applyMeta('department', input.department);
    applyMeta('pronouns', input.pronouns);
    applyMeta('timezone', input.timezone);
    applyMeta('locale', input.locale);
    applyMeta('phone', input.phone);
    applyMeta('bio', input.bio);

    if (metadataTouched) {
      updateData.metadata = Object.keys(metadata).length ? metadata : Prisma.JsonNull;
    }

  const shouldUpdate = Object.keys(updateData as Record<string, unknown>).length > 0;
    const updated = shouldUpdate
      ? await prisma.user.update({ where: { id: userId }, data: updateData })
      : existing;
    const roles: string[] = Array.isArray(req.user?.roles) ? req.user.roles : [];
    const permissions: string[] = Array.isArray(req.user?.permissions) ? req.user.permissions : [];
  const responseMetadata = parseUserMetadata((updated as any).metadata);

    return res.json({
      id: updated.id,
      email: updated.email,
      name: updated.name,
      image: updated.image,
      emailVerified: updated.emailVerified,
      roles,
      permissions,
      metadata: responseMetadata ?? null,
      lastLoginAt: updated.lastLoginAt,
      createdAt: updated.createdAt,
      updatedAt: updated.updatedAt,
    });
  } catch (err: any) {
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

// Diagnostics: report active auth mode and useful details to debug auth locally/in prod
router.get('/mode', (req: any, res: Response) => {
  const authMode = (process.env.AUTH_MODE || 'jwt').toLowerCase();
  const cookies = req.cookies || {};
  const sessionCookieName = process.env.SESSION_NAME || 'psrs.sid';

  // Cookies presence
  const hasSessionCookie = typeof cookies[sessionCookieName] === 'string' && cookies[sessionCookieName].length > 0;
  const hasAccessCookie = typeof cookies['accessToken'] === 'string' && cookies['accessToken'].length > 0;
  const hasRefreshCookie = typeof cookies['refreshToken'] === 'string' && cookies['refreshToken'].length > 0;

  // Decode access claims (non-sensitive) if present
  let accessClaims: any = null;
  if (hasAccessCookie) {
    try {
    const decoded = jwt.decode(String(cookies['accessToken']));
      if (decoded && typeof decoded === 'object') {
        const d = decoded as Record<string, any>;
        accessClaims = {
          sub: d.sub,
          typ: d.typ,
          iat: d.iat,
          exp: d.exp,
        };
      }
  } catch {
      accessClaims = null;
    }
  }

  // Providers config summary (no secrets)
  // Read provider enable flags from settings synchronously via cached env? We can only check env here; adjust enabled with settings via req.app locals if needed.
  // For now, include settings flag snapshot by querying Prisma (best-effort, non-blocking)
  const googleEnabled = true;
  const githubEnabled = true;
  try {
    // These reads are async in /mode route, but we'll leave them best-effort using synchronous defaults and override in thenable
  } catch {}

  const google = {
    configured: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REDIRECT_URI) && googleEnabled,
    redirectUri: process.env.GOOGLE_REDIRECT_URI || null,
    scope: 'openid email profile',
    hasClientId: Boolean(process.env.GOOGLE_CLIENT_ID),
    hasClientSecret: Boolean(process.env.GOOGLE_CLIENT_SECRET),
  };
  const github = {
    configured: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET && process.env.GITHUB_REDIRECT_URI) && githubEnabled,
    redirectUri: process.env.GITHUB_REDIRECT_URI || null,
    scope: 'read:user user:email',
    hasClientId: Boolean(process.env.GITHUB_CLIENT_ID),
    hasClientSecret: Boolean(process.env.GITHUB_CLIENT_SECRET),
  };

  // Current user info (id/roles/perms) if middleware populated it
  const u = req.user && typeof req.user === 'object' ? req.user : null;
  const user = u ? {
    id: u.id ?? u.sub ?? null,
    roles: Array.isArray(u.roles) ? u.roles : [],
    permissions: Array.isArray(u.permissions) ? u.permissions : [],
  } : null;

  const payload: any = {
    authMode,
    environment: {
      nodeEnv: process.env.NODE_ENV || 'development',
      corsOrigin: process.env.CORS_ORIGIN || '',
      cookieDomain: process.env.COOKIE_DOMAIN || '',
    },
    cookies: {
      session: { name: sessionCookieName, present: hasSessionCookie },
      accessToken: { present: hasAccessCookie },
      refreshToken: { present: hasRefreshCookie },
      csrfToken: { present: Boolean(cookies['csrfToken']) },
    },
    session: {
      enabled: authMode === 'session',
  id: authMode === 'session' ? (typeof req.sessionID === 'string' ? req.sessionID : null) : null,
      isAuthenticated: typeof req.isAuthenticated === 'function' ? req.isAuthenticated() : undefined,
      ttlDays: process.env.SESSION_TTL_DAYS ? Number(process.env.SESSION_TTL_DAYS) : undefined,
    },
    jwt: {
      enabled: authMode === 'jwt',
      accessClaims,
    },
    providers: { google, github },
    redirects: {
      success: process.env.OAUTH_SUCCESS_REDIRECT || null,
      failure: process.env.OAUTH_FAILURE_REDIRECT || null,
    },
    user,
  };

  // Try to override provider-enabled flags from settings (non-blocking)
  void (async () => {
    try {
      const authSettings = await prisma.setting.findMany({ where: { category: 'auth' } });
      const map = new Map(authSettings.map((s: any) => [s.key, s.value]));
      const g = Boolean(map.get('google'));
      const gh = Boolean(map.get('github'));
      payload.providers.google.configured = payload.providers.google.configured && g;
      payload.providers.github.configured = payload.providers.github.configured && gh;
    } catch {}
    res.json(payload);
  })();
});

// -----------------------------
// OAuth (stateless) start endpoints with provider toggle enforcement
// -----------------------------

function generateState(): string {
  return crypto.randomBytes(16).toString('hex');
}

function isOAuthProvider(p: string): p is 'google' | 'github' {
  return p === 'google' || p === 'github';
}

async function isProviderEnabled(provider: 'google' | 'github'): Promise<boolean> {
  try {
    const s = await prisma.setting.findUnique({ where: { category_key: { category: 'auth', key: provider } } as any });
    return Boolean(s?.value ?? true);
  } catch {
    return true;
  }
}

router.get('/oauth/:provider/start', async (req: any, res: Response) => {
  try {
    const provider = String(req.params.provider);
    if (!isOAuthProvider(provider)) return res.status(404).json({ error: 'provider not supported' });
    const prov: 'google' | 'github' = provider;
    const enabled = await isProviderEnabled(prov);
    if (!enabled) return res.status(403).json({ error: `${provider} login disabled` });

    const state = generateState();
    res.cookie('oauth_state', state, { ...cookieBase(), httpOnly: true, maxAge: 10 * 60 * 1000 });

    if (prov === 'google') {
      const clientId = process.env.GOOGLE_CLIENT_ID;
      const redirectUri = process.env.GOOGLE_REDIRECT_URI;
      if (!clientId || !redirectUri) return res.status(500).json({ error: 'google not configured' });
      const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('scope', 'openid email profile');
      authUrl.searchParams.set('state', state);
      return res.redirect(302, authUrl.toString());
    } else {
      const clientId = process.env.GITHUB_CLIENT_ID;
      const redirectUri = process.env.GITHUB_REDIRECT_URI;
      if (!clientId || !redirectUri) return res.status(500).json({ error: 'github not configured' });
      const authUrl = new URL('https://github.com/login/oauth/authorize');
      authUrl.searchParams.set('client_id', clientId);
      authUrl.searchParams.set('redirect_uri', redirectUri);
      authUrl.searchParams.set('scope', 'read:user user:email');
      authUrl.searchParams.set('state', state);
      return res.redirect(302, authUrl.toString());
    }
  } catch (err: any) {
    try { req.log?.error({ err }, 'oauth start failed'); } catch {}
  return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : INTERNAL_ERROR });
  }
});

// ---------------------------------------------
// OAuth callback for Google/GitHub
// - Validates state (double-submit cookie)
// - Exchanges code for tokens
// - Fetches profile and links/creates user + Account
// - Issues access/refresh cookies and redirects
// ---------------------------------------------
  router.get('/oauth/:provider/callback', async (req: Request, res: Response) => {
  const successRedirect = process.env.OAUTH_SUCCESS_REDIRECT || '/';
  const failureRedirect = process.env.OAUTH_FAILURE_REDIRECT || '/login?error=oauth_failed';
  const provider = String(req.params.provider);
  try {
    if (!isOAuthProvider(provider)) return res.redirect(302, failureRedirect);
    const prov: 'google' | 'github' = provider;
    const enabled = await isProviderEnabled(prov);
    if (!enabled) return res.redirect(302, `${failureRedirect}&reason=disabled`);

  const { code, state } = req.query as { code?: string; state?: string };
    if (!code || !state) return res.redirect(302, `${failureRedirect}&reason=missing_params`);
    const cookieState = req.cookies?.oauth_state;
    // Clear state cookie regardless of outcome
    res.cookie('oauth_state', '', { ...cookieBase(), httpOnly: true, maxAge: 0 });
    if (!cookieState || cookieState !== state) {
    await logAudit(null, `auth.oauth.${provider}.state_mismatch`, { ip: req.ip, get: req.get.bind(req) });
      return res.redirect(302, `${failureRedirect}&reason=state_mismatch`);
    }

    // Token exchange and profile fetch per provider
    type OAuthTokens = { access_token: string; refresh_token?: string; expires_in?: number; id_token?: string; token_type?: string; scope?: string };
    let tokens: OAuthTokens | null = null;
    let profile: any = null;
    let providerAccountId: string | null = null;
    let email: string | null = null;
    let emailVerified: boolean | null = null;
    let name: string | null = null;
    let image: string | null = null;

    if (prov === 'google') {
      const clientId = process.env.GOOGLE_CLIENT_ID;
      const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
      const redirectUri = process.env.GOOGLE_REDIRECT_URI;
      if (!clientId || !clientSecret || !redirectUri) return res.redirect(302, `${failureRedirect}&reason=not_configured`);
      const body = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code: String(code),
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      });
      const r = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      } as RequestInit);
      if (!r.ok) {
        await logAudit(null, 'auth.oauth.google.token_error', req as { ip?: string; get: (name: string) => string | undefined }, { status: r.status });
        return res.redirect(302, `${failureRedirect}&reason=token_exchange_failed`);
      }
      tokens = await r.json();
      // Prefer OIDC userinfo for normalized fields
      if (!tokens || !tokens.access_token) {
        await logAudit(null, 'auth.oauth.google.missing_access_token', req as { ip?: string; get: (name: string) => string | undefined });
        return res.redirect(302, `${failureRedirect}&reason=missing_access_token`);
      }
      const accessToken = tokens.access_token;
      const u = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      } as RequestInit);
      if (!u.ok) {
        await logAudit(null, 'auth.oauth.google.userinfo_error', req as { ip?: string; get: (name: string) => string | undefined }, { status: u.status });
        return res.redirect(302, `${failureRedirect}&reason=userinfo_failed`);
      }
      profile = await u.json();
      providerAccountId = String(profile.sub);
      email = typeof profile.email === 'string' ? profile.email : null;
      emailVerified = Boolean(profile.email_verified ?? false);
      name = typeof profile.name === 'string' ? profile.name : null;
      image = typeof profile.picture === 'string' ? profile.picture : null;
    } else {
      // github
      const clientId = process.env.GITHUB_CLIENT_ID;
      const clientSecret = process.env.GITHUB_CLIENT_SECRET;
      const redirectUri = process.env.GITHUB_REDIRECT_URI;
      if (!clientId || !clientSecret || !redirectUri) return res.redirect(302, `${failureRedirect}&reason=not_configured`);
      const body = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code: String(code),
        redirect_uri: redirectUri,
      });
      const r = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body,
      } as RequestInit);
      if (!r.ok) {
        await logAudit(null, 'auth.oauth.github.token_error', req as { ip?: string; get: (name: string) => string | undefined }, { status: r.status });
        return res.redirect(302, `${failureRedirect}&reason=token_exchange_failed`);
      }
      tokens = await r.json();

      if (!tokens || !tokens.access_token) {
        await logAudit(null, 'auth.oauth.github.missing_access_token', req as { ip?: string; get: (name: string) => string | undefined });
        return res.redirect(302, `${failureRedirect}&reason=missing_access_token`);
      }
      const accessToken = tokens.access_token;
      const u = await fetch('https://api.github.com/user', {
        headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'psrs-app' },
      } as RequestInit);
      if (!u.ok) {
        await logAudit(null, 'auth.oauth.github.user_error', req as { ip?: string; get: (name: string) => string | undefined }, { status: u.status });
        return res.redirect(302, `${failureRedirect}&reason=userinfo_failed`);
      }
      const up = await u.json();
      providerAccountId = String(up.id);
      name = typeof up.name === 'string' ? up.name : (typeof up.login === 'string' ? up.login : null);
      image = typeof up.avatar_url === 'string' ? up.avatar_url : null;

      // attempt to get verified email
      try {
        const e = await fetch('https://api.github.com/user/emails', {
          headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'psrs-app', Accept: 'application/vnd.github+json' },
        } as RequestInit);
        if (e.ok) {
          const emails = await e.json();
          const primary = Array.isArray(emails) ? emails.find((x: any) => x.primary) : null;
          if (primary?.email) {
            email = String(primary.email);
            emailVerified = Boolean(primary.verified);
          } else if (Array.isArray(emails) && emails.length) {
            email = String(emails[0].email);
            emailVerified = Boolean(emails[0].verified);
          }
        }
      } catch {}
    }

  if (!providerAccountId) return res.redirect(302, `${failureRedirect}&reason=missing_account_id`);

    // Link or create user using AuthService when available
    let user: any = null;
  const authSvcOauth = resolveAuthService(req);
  const existingAccount = authSvcOauth ? await authSvcOauth.prisma.account.findUnique({ where: { provider_providerAccountId: { provider, providerAccountId } } }) : await prisma.account.findUnique({ where: { provider_providerAccountId: { provider, providerAccountId } } });
    if (existingAccount) {
      user = authSvcOauth ? await authSvcOauth.prisma.user.findUnique({ where: { id: existingAccount.userId } }) : await prisma.user.findUnique({ where: { id: existingAccount.userId } });
    } else {
      if (email) {
        const byEmail = authSvcOauth ? await authSvcOauth.findUserByEmail(email) : await prisma.user.findUnique({ where: { email } });
        if (byEmail) user = byEmail;
      }
      if (!user) {
        const oauthCreate: Prisma.UserCreateInput | Prisma.UserUncheckedCreateInput = {
          email: email || `${provider}:${providerAccountId}@user.local`,
          name: name || undefined,
          image: image || undefined,
          emailVerified: emailVerified ? new Date() : null,
        } as Prisma.UserCreateInput;
        user = authSvcOauth ? await authSvcOauth.createUser(oauthCreate) : await prisma.user.create({ data: oauthCreate });
      }
      if (authSvcOauth) {
        await authSvcOauth.prisma.account.create({ data: { userId: user.id, provider, providerAccountId, accessToken: tokens?.access_token, refreshToken: tokens?.refresh_token, tokenType: tokens?.token_type, scope: tokens?.scope, profile } });
      } else {
        await prisma.account.create({ data: { userId: user.id, provider, providerAccountId, accessToken: tokens?.access_token, refreshToken: tokens?.refresh_token, tokenType: tokens?.token_type, scope: tokens?.scope, profile } });
      }
    }

    // If email just verified by provider and user lacked it, mark verified
    if (emailVerified && !user.emailVerified) {
      try {
        await prisma.user.update({ where: { id: user.id }, data: { emailVerified: new Date() } });
      } catch {}
    }

    // Issue cookies
    const access = signAccessToken(String(user.id));
  const rt = await createRefreshToken(req, String(user.id));
    setAuthCookies(res, access, rt.token, rt.maxAgeMs);

    await logAudit(String(user.id), `auth.oauth.${provider}.success`, req as { ip?: string; get: (name: string) => string | undefined }, { providerAccountId });
    return res.redirect(302, successRedirect);
  } catch (err: any) {
    try { req.log?.error({ err }, 'oauth callback failed'); } catch {}
    return res.redirect(302, `${failureRedirect}&reason=exception`);
  }
});

router.get('/security', requireAuth, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const snapshot = await svc.getAccountSecuritySnapshot(userId);
  if (!snapshot) return res.status(404).json({ error: ERROR_USER_NOT_FOUND });
    return res.json({ snapshot });
  } catch (err) {
    try { (req as any).log?.error?.({ err }, 'security snapshot failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/password', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = ChangePasswordSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.changePassword(userId, parse.data, {
      currentRefreshToken: req.cookies?.refreshToken as string | undefined,
      requestMeta: { ipAddress: req.ip, userAgent: req.get(HEADER_UA) || undefined },
    });
    return res.status(204).send();
  } catch (err) {
    if (err instanceof PasswordChangeError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'security password change failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.put('/security/recovery', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = UpdateRecoverySchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const updated = await svc.updateRecoverySettings(userId, parse.data);
  if (!updated) return res.status(404).json({ error: ERROR_USER_NOT_FOUND });
    return res.json({ recovery: updated });
  } catch (err) {
    try { (req as any).log?.error?.({ err }, 'security recovery update failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.put('/security/alerts', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = UpdateAlertsSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const updated = await svc.updateAlertSettings(userId, parse.data);
  if (!updated) return res.status(404).json({ error: ERROR_USER_NOT_FOUND });
    return res.json({ alerts: updated });
  } catch (err) {
    try { (req as any).log?.error?.({ err }, 'security alerts update failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.get('/security/sessions', requireAuth, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const sessions = await svc.listSessions(userId);
    return res.json({ summary: sessions.summary, sessions: sessions.list });
  } catch (err) {
    try { (req as any).log?.error?.({ err }, 'security sessions failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/sessions/revoke', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = RevokeSessionSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.revokeSession(userId, parse.data.sessionId);
    return res.status(204).send();
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'security session revoke failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/sessions/revoke-all', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.revokeAllSessions(userId, req.cookies?.refreshToken as string | undefined);
    return res.status(204).send();
  } catch (err) {
    try { (req as any).log?.error?.({ err }, 'security sessions revoke-all failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/sessions/trust', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = TrustSessionSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.setSessionTrust(userId, parse.data.sessionId, parse.data.trust ?? true, { ipAddress: req.ip, userAgent: req.get(HEADER_UA) || undefined });
    return res.status(204).send();
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'security session trust failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/mfa/totp/enroll', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = TotpEnrollSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const prompt = await svc.startTotpEnrollment(userId, parse.data);
    return res.json(prompt);
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'totp enrollment failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/mfa/totp/confirm', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = TotpConfirmSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const result = await svc.confirmTotpEnrollment(userId, parse.data);
    return res.json(result);
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'totp confirm failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/mfa/totp/:factorId/regenerate', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const factorId = String(req.params?.factorId || '').trim();
  if (!factorId) return res.status(400).json({ error: ERROR_FACTOR_ID_REQUIRED });
  const parse = TotpRotateSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const prompt = await svc.regenerateTotpFactor(userId, factorId, parse.data);
    return res.json(prompt);
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'totp regenerate failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/mfa/backup-codes/regenerate', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = BackupCodesRegenerateSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    const result = await svc.regenerateBackupCodes(userId, parse.data.factorId);
    return res.json(result);
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'backup codes regenerate failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/mfa/:factorId/disable', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const factorId = String(req.params?.factorId || '').trim();
  if (!factorId) return res.status(400).json({ error: ERROR_FACTOR_ID_REQUIRED });
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.disableMfaFactor(userId, factorId);
    return res.status(204).send();
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'mfa disable failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/mfa/:factorId/enable', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const factorId = String(req.params?.factorId || '').trim();
  if (!factorId) return res.status(400).json({ error: ERROR_FACTOR_ID_REQUIRED });
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.enableMfaFactor(userId, factorId);
    return res.status(204).send();
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'mfa enable failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.delete('/security/mfa/:factorId', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const factorId = String(req.params?.factorId || '').trim();
  if (!factorId) return res.status(400).json({ error: ERROR_FACTOR_ID_REQUIRED });
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.deleteMfaFactor(userId, factorId);
    return res.status(204).send();
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'mfa delete failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.post('/security/sessions/revoke', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = RevokeSessionSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveSecurityService(req) ?? new SecurityService({ prisma });
  try {
    await svc.revokeSession(userId, parse.data.sessionId);
    return res.status(204).send();
  } catch (err) {
    if (err instanceof SecurityOperationError) {
      return res.status(err.status).json({ error: err.message });
    }
    try { (req as any).log?.error?.({ err }, 'security session revoke failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.get('/notifications', requireAuth, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const svc = resolveNotificationService(req) ?? new NotificationService();
  try {
    const settings = await svc.getNotificationSettings(userId);
  if (!settings) return res.status(404).json({ error: ERROR_USER_NOT_FOUND });
    const parsed = NotificationSettingsSchema.safeParse(settings);
    if (!parsed.success) {
      try { (req as any).log?.error?.({ issues: parsed.error.issues }, 'notifications schema validation failed'); } catch {}
      return res.status(500).json({ error: INTERNAL_ERROR });
    }
    return res.json({ settings: parsed.data });
  } catch (err) {
    try { (req as any).log?.error?.({ err }, 'notifications fetch failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

router.put('/notifications', requireAuth, validateCsrf, async (req: Request, res: Response) => {
  const userId = (req as any).user?.id as string | undefined;
  if (!userId) return res.status(401).json({ error: 'unauthorized' });
  const parse = NotificationSettingsUpdateSchema.safeParse(req.body || {});
  if (!parse.success) {
    return res.status(400).json({ error: ERROR_INVALID_PAYLOAD, details: parse.error.flatten() });
  }
  const svc = resolveNotificationService(req) ?? new NotificationService();
  try {
    const updated = await svc.updateNotificationSettings(userId, parse.data);
  if (!updated) return res.status(404).json({ error: ERROR_USER_NOT_FOUND });
    const parsed = NotificationSettingsSchema.safeParse(updated);
    if (!parsed.success) {
      try { (req as any).log?.error?.({ issues: parsed.error.issues }, 'notifications schema validation failed'); } catch {}
      return res.status(500).json({ error: INTERNAL_ERROR });
    }
    return res.json({ settings: parsed.data });
  } catch (err) {
    try { (req as any).log?.error?.({ err }, 'notifications update failed'); } catch {}
    const message = process.env.NODE_ENV === 'test' ? String((err as any)?.message || err) : INTERNAL_ERROR;
    return res.status(500).json({ error: message });
  }
});

export default router;
