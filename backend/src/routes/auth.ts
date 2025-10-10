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
    if (!email || !password || !name) return res.status(400).json({ error: 'name, email and password are required' });
    // Basic server-side password policy: 8+ chars, upper, lower, digit, special
    const strong = password.length >= 8 
      && /[A-Z]/.test(password) 
      && /[a-z]/.test(password) 
      && /[0-9]/.test(password) 
      && /[^A-Za-z0-9]/.test(password);
    if (!strong) return res.status(400).json({ error: 'password does not meet complexity requirements' });
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: 'account already exists' });
    const hashOpts = process.env.NODE_ENV === 'test'
      ? { type: argon2.argon2id, timeCost: 2, memoryCost: 1024, parallelism: 1 }
      : { type: argon2.argon2id };
    const passwordHash = (await (argon2 as any).hash(password, hashOpts)) as string;
  const user = await prisma.user.create({ data: { email, passwordHash, name } });
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

router.get('/me', async (req: any, res) => {
  try {
    const userId = req.user?.id || req.user?.sub;
    if (!userId) return res.status(401).json({ authenticated: false });
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(401).json({ authenticated: false });
    const roles: string[] = Array.isArray(req.user?.roles) ? req.user.roles : [];
    const permissions: string[] = Array.isArray(req.user?.permissions) ? req.user.permissions : [];
    return res.json({ id: user.id, email: user.email, name: user.name, emailVerified: user.emailVerified, roles, permissions });
  } catch (err: any) {
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

// Diagnostics: report active auth mode and useful details to debug auth locally/in prod
router.get('/mode', (req: any, res) => {
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
      const decoded = jwt.decode(cookies['accessToken']);
      if (decoded && typeof decoded === 'object') {
        accessClaims = {
          sub: (decoded as any).sub,
          typ: (decoded as any).typ,
          iat: (decoded as any).iat,
          exp: (decoded as any).exp,
        };
      }
    } catch (_) {
      accessClaims = null;
    }
  }

  // Providers config summary (no secrets)
  const google = {
    configured: Boolean(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REDIRECT_URI),
    redirectUri: process.env.GOOGLE_REDIRECT_URI || null,
    scope: 'openid email profile',
    hasClientId: Boolean(process.env.GOOGLE_CLIENT_ID),
    hasClientSecret: Boolean(process.env.GOOGLE_CLIENT_SECRET),
  };
  const github = {
    configured: Boolean(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET && process.env.GITHUB_REDIRECT_URI),
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

  res.json({
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
      id: authMode === 'session' ? (req as any).sessionID || null : null,
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
  });
});

export default router;
