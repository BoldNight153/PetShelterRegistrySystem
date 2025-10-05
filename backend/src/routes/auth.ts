import { Router } from 'express';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import jwt, { SignOptions, Secret } from 'jsonwebtoken';

const prisma: any = new PrismaClient();

const router = Router();

// Simple andi-CSRF implementation using double-submit cookie pattern.
// GET /auth/csrf - issues a CSRF token and sets a cookie (httpOnly=false) so the browser can send it back via header.
router.get('/csrf', (req, res) => {
  const secret = process.env.CSRF_SECRET || 'dev-csrf-secret';
  const token = crypto.randomBytes(16).toString('hex');
  // Optionally sign; here we attach a simple HMAC for tamper detection
  const hmac = crypto.createHmac('sha256', secret).update(token).digest('hex');
  const csrfToken = `${token}.${hmac}`;
  // Non-HttpOnly so clients can read and reflect in header; SameSite=Lax is fine
  res.cookie('csrfToken', csrfToken, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 60 * 60 * 1000,
    path: '/',
  });
  res.json({ csrfToken });
});

// Middleware to validate CSRF on state-changing requests
function validateCsrf(req: any, res: any, next: any) {
  const secret = process.env.CSRF_SECRET || 'dev-csrf-secret';
  const fromCookie = req.cookies?.csrfToken;
  const fromHeader = req.header('x-csrf-token');
  if (!fromCookie || !fromHeader) return res.status(403).json({ error: 'CSRF token missing' });
  const [token, sig] = String(fromCookie).split('.');
  const expected = crypto.createHmac('sha256', secret).update(token).digest('hex');
  if (sig !== expected || fromHeader !== fromCookie) {
    return res.status(403).json({ error: 'CSRF token invalid' });
  }
  return next();
}

// Helpers
function cookieBase() {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax' as const,
    path: '/',
  };
}

function signAccessToken(userId: string) {
  const secret: Secret = (process.env.JWT_ACCESS_SECRET || 'dev-access-secret') as Secret;
  const payload = { sub: userId, typ: 'access' } as Record<string, any>;
  const opts: SignOptions = { expiresIn: (process.env.ACCESS_TTL as any) || '15m' };
  return jwt.sign(payload, secret, opts);
}

function generateToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

async function createRefreshToken(userId: string, userAgent?: string, ipAddress?: string) {
  const token = crypto.randomBytes(32).toString('hex');
  const days = Number(process.env.REFRESH_DAYS || 30);
  const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
  await prisma.refreshToken.create({
    data: {
      userId,
      token,
      expiresAt,
      userAgent,
      ipAddress,
    },
  });
  return token;
}

function setAuthCookies(res: any, accessToken: string, refreshToken: string) {
  // access cookie: short TTL via JWT exp; no maxAge needed
  res.cookie('accessToken', accessToken, cookieBase());
  // refresh cookie: explicitly set maxAge
  const days = Number(process.env.REFRESH_DAYS || 30);
  res.cookie('refreshToken', refreshToken, { ...cookieBase(), maxAge: days * 24 * 60 * 60 * 1000 });
}

function clearAuthCookies(res: any) {
  // Clear both cookies by setting Max-Age=0
  const base = cookieBase();
  res.cookie('accessToken', '', { ...base, maxAge: 0 });
  res.cookie('refreshToken', '', { ...base, maxAge: 0 });
}

async function logAudit(userId: string | null, action: string, req: any, metadata?: any) {
  try {
    await prisma.auditLog.create({
      data: {
        userId: userId || undefined,
        action,
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || undefined,
        metadata,
      },
    });
  } catch (_) {
    // best-effort; do not block auth flow on audit failure
  }
}

async function revokeAllRefreshTokens(userId: string) {
  try {
    await prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
  } catch (_) {
    // ignore
  }
}

// Register: email/password
router.post('/register', validateCsrf, async (req, res) => {
  try {
    const { email, password, name } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: 'account already exists' });
    const hashOpts = process.env.NODE_ENV === 'test'
      ? { type: argon2.argon2id, timeCost: 2, memoryCost: 1024, parallelism: 1 }
      : { type: argon2.argon2id };
    const passwordHash = (await (argon2 as any).hash(password, hashOpts)) as string;
    const user = await prisma.user.create({ data: { email, passwordHash, name: name || null } });
    await logAudit(user.id, 'auth.register', req);
    const access = signAccessToken(user.id);
    const refresh = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
    setAuthCookies(res, access, refresh);
    return res.status(201).json({ id: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified });
  } catch (err: any) {
    // Log detailed error but avoid leaking internals in production
    try {
      (req as any).log?.error({ err }, 'register failed');
    } catch (_) {
      // no-op
    }
    const message = process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error';
    return res.status(500).json({ error: message });
  }
});

// Login: email/password
router.post('/login', validateCsrf, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.passwordHash) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await argon2.verify(user.passwordHash, password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    await logAudit(user.id, 'auth.login', req);
    const access = signAccessToken(user.id);
    const refresh = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
    setAuthCookies(res, access, refresh);
    return res.json({ id: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified });
  } catch (err: any) {
    try {
      (req as any).log?.error({ err }, 'login failed');
    } catch (_) {}
    const message = process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error';
    return res.status(500).json({ error: message });
  }
});

router.post('/logout', validateCsrf, async (req, res) => {
  try {
    const rt = req.cookies?.refreshToken as string | undefined;
    if (rt) {
      try {
        const existing = await prisma.refreshToken.findUnique({ where: { token: rt } });
        if (existing && !existing.revokedAt) {
          await prisma.refreshToken.update({ where: { token: rt }, data: { revokedAt: new Date() } });
          await logAudit(existing.userId, 'auth.logout', req, { reason: 'user initiated' });
        }
      } catch (_) {
        // ignore revocation errors on logout
      }
    }
    clearAuthCookies(res);
    return res.status(204).send();
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'logout failed'); } catch (_) {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

router.post('/refresh', validateCsrf, async (req, res) => {
  try {
    const rt = req.cookies?.refreshToken as string | undefined;
    if (!rt) return res.status(401).json({ error: 'missing refresh token' });
    const existing = await prisma.refreshToken.findUnique({ where: { token: rt } });
    if (!existing) return res.status(401).json({ error: 'invalid refresh token' });
    if (existing.revokedAt) return res.status(401).json({ error: 'refresh token revoked' });
    if (existing.expiresAt <= new Date()) return res.status(401).json({ error: 'refresh token expired' });

    // rotate
    const newToken = await createRefreshToken(existing.userId, req.get('user-agent') || undefined, req.ip);
    await prisma.refreshToken.update({ where: { token: rt }, data: { revokedAt: new Date(), replacedByToken: newToken } });

    const access = signAccessToken(existing.userId);
    setAuthCookies(res, access, newToken);
    await logAudit(existing.userId, 'auth.refresh', req, { rotatedFrom: rt });
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'refresh failed'); } catch (_) {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

router.post('/request-email-verification', validateCsrf, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email is required' });
    const user = await (prisma as any).user.findUnique({ where: { email } });
    // Always respond 200 to avoid enumeration
    if (!user) return res.json({ ok: true });
    if (user.emailVerified) return res.json({ ok: true });
    const token = generateToken();
    const ttlMin = Number(process.env.EMAIL_VERIFICATION_TTL_MIN || 60 * 24); // default 24h
    const expiresAt = new Date(Date.now() + ttlMin * 60 * 1000);
    await (prisma as any).verificationToken.create({
      data: { identifier: email, token, type: 'email_verify', expiresAt },
    });
    await logAudit(user.id, 'auth.email_verification.request', req);
    try { (req as any).log?.info({ email, token }, 'email verification token issued'); } catch (_) {}
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'request-email-verification failed'); } catch (_) {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

router.post('/verify-email', validateCsrf, async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token is required' });
    const vt = await (prisma as any).verificationToken.findUnique({ where: { token } });
    if (!vt || vt.type !== 'email_verify') return res.status(400).json({ error: 'invalid token' });
    if (vt.consumedAt) return res.status(400).json({ error: 'token already used' });
    if (vt.expiresAt <= new Date()) return res.status(400).json({ error: 'token expired' });
    const user = await (prisma as any).user.findUnique({ where: { email: vt.identifier } });
    if (!user) return res.status(400).json({ error: 'invalid token' });
    const updated = await (prisma as any).user.update({ where: { id: user.id }, data: { emailVerified: new Date() } });
    await (prisma as any).verificationToken.update({ where: { id: vt.id }, data: { consumedAt: new Date() } });
    await revokeAllRefreshTokens(user.id);
    await logAudit(user.id, 'auth.email_verification.verified', req);
    // issue fresh session
    const access = signAccessToken(user.id);
    const refresh = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
    setAuthCookies(res, access, refresh);
    return res.json({ id: updated.id, email: updated.email, emailVerified: updated.emailVerified });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'verify-email failed'); } catch (_) {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

router.post('/request-password-reset', validateCsrf, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email is required' });
  const user = await (prisma as any).user.findUnique({ where: { email } });
    // Always respond 200 to avoid user enumeration
    if (!user) return res.json({ ok: true });
    const token = generateToken();
    const ttl = Number(process.env.PASSWORD_RESET_TTL_MIN || 60); // minutes
    const expiresAt = new Date(Date.now() + ttl * 60 * 1000);
    await (prisma as any).verificationToken.create({
      data: { identifier: email, token, type: 'password_reset', expiresAt },
    });
    await logAudit(user.id, 'auth.password_reset.request', req);
    // TODO: integrate email provider; for now, log only
    try { (req as any).log?.info({ email, token }, 'password reset token issued'); } catch (_) {}
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'request-password-reset failed'); } catch (_) {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

router.post('/reset-password', validateCsrf, async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) return res.status(400).json({ error: 'token and password are required' });
  const vt = await (prisma as any).verificationToken.findUnique({ where: { token } });
    if (!vt || vt.type !== 'password_reset') return res.status(400).json({ error: 'invalid token' });
    if (vt.consumedAt) return res.status(400).json({ error: 'token already used' });
    if (vt.expiresAt <= new Date()) return res.status(400).json({ error: 'token expired' });
  const user = await (prisma as any).user.findUnique({ where: { email: vt.identifier } });
    if (!user) return res.status(400).json({ error: 'invalid token' });
    const hashOpts = process.env.NODE_ENV === 'test'
      ? { type: argon2.argon2id, timeCost: 2, memoryCost: 1024, parallelism: 1 }
      : { type: argon2.argon2id };
    const passwordHash = (await (argon2 as any).hash(password, hashOpts)) as string;
  await (prisma as any).user.update({ where: { id: user.id }, data: { passwordHash } });
  await (prisma as any).verificationToken.update({ where: { id: vt.id }, data: { consumedAt: new Date() } });
    await revokeAllRefreshTokens(user.id);
    await logAudit(user.id, 'auth.password_reset.reset', req);
    // issue new session cookies
    const access = signAccessToken(user.id);
    const refresh = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
    setAuthCookies(res, access, refresh);
    return res.json({ ok: true });
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'reset-password failed'); } catch (_) {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

router.get('/me', (req, res) => {
  return res.json({ authenticated: false });
});

export default router;
