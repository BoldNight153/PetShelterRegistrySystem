import { Router } from 'express';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import jwt, { SignOptions, Secret } from 'jsonwebtoken';
import { resetPasswordEmailTemplate, sendMail, verificationEmailTemplate } from '../lib/email';

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

async function createRefreshToken(userId: string, userAgent?: string, ipAddress?: string): Promise<{ token: string; expiresAt: Date; maxAgeMs: number }>
{
  const token = crypto.randomBytes(32).toString('hex');
  // Prefer settings.security.sessionMaxAgeMin, fallback to env REFRESH_DAYS (days)
  let expiresAt: Date;
  let maxAgeMs: number;
  try {
    const s = await (prisma as any).setting.findUnique({ where: { category_key: { category: 'security', key: 'sessionMaxAgeMin' } } });
    const minutes = Number(s?.value ?? 0);
    if (Number.isFinite(minutes) && minutes > 0) {
      maxAgeMs = minutes * 60 * 1000;
      expiresAt = new Date(Date.now() + maxAgeMs);
    } else {
      const days = Number(process.env.REFRESH_DAYS || 30);
      maxAgeMs = days * 24 * 60 * 60 * 1000;
      expiresAt = new Date(Date.now() + maxAgeMs);
    }
  } catch (_) {
    const days = Number(process.env.REFRESH_DAYS || 30);
    maxAgeMs = days * 24 * 60 * 60 * 1000;
    expiresAt = new Date(Date.now() + maxAgeMs);
  }
  await prisma.refreshToken.create({
    data: {
      userId,
      token,
      expiresAt,
      userAgent,
      ipAddress,
    },
  });
  return { token, expiresAt, maxAgeMs };
}

function setAuthCookies(res: any, accessToken: string, refreshToken: string, refreshMaxAgeMs?: number) {
  // access cookie: short TTL via JWT exp; no maxAge needed
  res.cookie('accessToken', accessToken, cookieBase());
  // refresh cookie: explicitly set maxAge
  const maxAge = typeof refreshMaxAgeMs === 'number' && refreshMaxAgeMs > 0
    ? refreshMaxAgeMs
    : Number(process.env.REFRESH_DAYS || 30) * 24 * 60 * 60 * 1000;
  res.cookie('refreshToken', refreshToken, { ...cookieBase(), maxAge });
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
  const rt = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
  setAuthCookies(res, access, rt.token, rt.maxAgeMs);
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
    // Enforce email verification if enabled via settings
    try {
      const setting = await (prisma as any).setting.findUnique({ where: { category_key: { category: 'security', key: 'requireEmailVerification' } } });
      const required = Boolean(setting?.value ?? true);
      if (required && !user.emailVerified) return res.status(403).json({ error: 'email verification required' });
    } catch (_) {}
    const ok = await argon2.verify(user.passwordHash, password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    await logAudit(user.id, 'auth.login', req);
  const access = signAccessToken(user.id);
  const rt = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
  setAuthCookies(res, access, rt.token, rt.maxAgeMs);
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
  const created = await createRefreshToken(existing.userId, req.get('user-agent') || undefined, req.ip);
  await prisma.refreshToken.update({ where: { token: rt }, data: { revokedAt: new Date(), replacedByToken: created.token } });

  const access = signAccessToken(existing.userId);
  setAuthCookies(res, access, created.token, created.maxAgeMs);
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
  const rt = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
  setAuthCookies(res, access, rt.token, rt.maxAgeMs);
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
  const rt = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
  setAuthCookies(res, access, rt.token, rt.maxAgeMs);
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
  // Read provider enable flags from settings synchronously via cached env? We can only check env here; adjust enabled with settings via req.app locals if needed.
  // For now, include settings flag snapshot by querying Prisma (best-effort, non-blocking)
  let googleEnabled = true;
  let githubEnabled = true;
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
  };

  // Try to override provider-enabled flags from settings (non-blocking)
  (async () => {
    try {
      const authSettings = await (prisma as any).setting.findMany({ where: { category: 'auth' } });
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

async function isProviderEnabled(provider: 'google' | 'github'): Promise<boolean> {
  try {
    const s = await (prisma as any).setting.findUnique({ where: { category_key: { category: 'auth', key: provider } } });
    return Boolean(s?.value ?? true);
  } catch {
    return true;
  }
}

router.get('/oauth/:provider/start', async (req: any, res) => {
  try {
    const provider = String(req.params.provider);
    if (provider !== 'google' && provider !== 'github') return res.status(404).json({ error: 'provider not supported' });
    const enabled = await isProviderEnabled(provider as any);
    if (!enabled) return res.status(403).json({ error: `${provider} login disabled` });

    const state = generateState();
    res.cookie('oauth_state', state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 10 * 60 * 1000,
    });

    if (provider === 'google') {
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
    try { (req as any).log?.error({ err }, 'oauth start failed'); } catch {}
    return res.status(500).json({ error: process.env.NODE_ENV === 'test' ? String(err?.message || err) : 'internal error' });
  }
});

// ---------------------------------------------
// OAuth callback for Google/GitHub
// - Validates state (double-submit cookie)
// - Exchanges code for tokens
// - Fetches profile and links/creates user + Account
// - Issues access/refresh cookies and redirects
// ---------------------------------------------
router.get('/oauth/:provider/callback', async (req: any, res) => {
  const successRedirect = process.env.OAUTH_SUCCESS_REDIRECT || '/';
  const failureRedirect = process.env.OAUTH_FAILURE_REDIRECT || '/login?error=oauth_failed';
  const provider = String(req.params.provider);
  try {
    if (provider !== 'google' && provider !== 'github') return res.redirect(302, failureRedirect);
    const enabled = await isProviderEnabled(provider as any);
    if (!enabled) return res.redirect(302, `${failureRedirect}&reason=disabled`);

    const { code, state } = req.query as any;
    if (!code || !state) return res.redirect(302, `${failureRedirect}&reason=missing_params`);
    const cookieState = req.cookies?.oauth_state;
    // Clear state cookie regardless of outcome
    res.cookie('oauth_state', '', { ...cookieBase(), httpOnly: true, maxAge: 0 });
    if (!cookieState || cookieState !== state) {
      await logAudit(null, `auth.oauth.${provider}.state_mismatch`, req);
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

    if (provider === 'google') {
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
      } as any);
      if (!r.ok) {
        await logAudit(null, 'auth.oauth.google.token_error', req, { status: r.status });
        return res.redirect(302, `${failureRedirect}&reason=token_exchange_failed`);
      }
      tokens = await r.json();
      // Prefer OIDC userinfo for normalized fields
      if (!tokens || !tokens.access_token) {
        await logAudit(null, 'auth.oauth.google.missing_access_token', req);
        return res.redirect(302, `${failureRedirect}&reason=missing_access_token`);
      }
      const accessToken = tokens.access_token as string;
      const u = await fetch('https://openidconnect.googleapis.com/v1/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      } as any);
      if (!u.ok) {
        await logAudit(null, 'auth.oauth.google.userinfo_error', req, { status: u.status });
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
      } as any);
      if (!r.ok) {
        await logAudit(null, 'auth.oauth.github.token_error', req, { status: r.status });
        return res.redirect(302, `${failureRedirect}&reason=token_exchange_failed`);
      }
      tokens = await r.json();

      if (!tokens || !tokens.access_token) {
        await logAudit(null, 'auth.oauth.github.missing_access_token', req);
        return res.redirect(302, `${failureRedirect}&reason=missing_access_token`);
      }
      const accessToken = tokens.access_token as string;
      const u = await fetch('https://api.github.com/user', {
        headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'psrs-app' },
      } as any);
      if (!u.ok) {
        await logAudit(null, 'auth.oauth.github.user_error', req, { status: u.status });
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
        } as any);
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

    // Link or create user
    let user: any = null;
    const existingAccount = await prisma.account.findUnique({ where: { provider_providerAccountId: { provider, providerAccountId } } });
    if (existingAccount) {
      user = await prisma.user.findUnique({ where: { id: existingAccount.userId } });
    } else {
      if (email) {
        const byEmail = await prisma.user.findUnique({ where: { email } });
        if (byEmail) {
          user = byEmail;
        }
      }
      if (!user) {
        user = await prisma.user.create({ data: { email: email || `${provider}:${providerAccountId}@user.local`, name: name || undefined, image: image || undefined, emailVerified: emailVerified ? new Date() : null } });
      }
      await prisma.account.create({ data: {
        userId: user.id,
        provider,
        providerAccountId,
        accessToken: tokens?.access_token,
        refreshToken: tokens?.refresh_token,
        tokenType: tokens?.token_type,
        scope: tokens?.scope,
        profile,
      }});
    }

    // If email just verified by provider and user lacked it, mark verified
    if (emailVerified && !user.emailVerified) {
      try {
        await prisma.user.update({ where: { id: user.id }, data: { emailVerified: new Date() } });
      } catch {}
    }

    // Issue cookies
    const access = signAccessToken(user.id);
    const rt = await createRefreshToken(user.id, req.get('user-agent') || undefined, req.ip);
    setAuthCookies(res, access, rt.token, rt.maxAgeMs);

    await logAudit(user.id, `auth.oauth.${provider}.success`, req, { providerAccountId });
    return res.redirect(302, successRedirect);
  } catch (err: any) {
    try { (req as any).log?.error({ err }, 'oauth callback failed'); } catch {}
    return res.redirect(302, `${failureRedirect}&reason=exception`);
  }
});

export default router;
