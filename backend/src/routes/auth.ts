import { Router } from 'express';
import crypto from 'crypto';

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

// Placeholders for Phase 1 endpoints
router.post('/register', validateCsrf, (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
});

router.post('/login', validateCsrf, (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
});

router.post('/logout', validateCsrf, (req, res) => {
  return res.status(204).send();
});

router.post('/refresh', validateCsrf, (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
});

router.post('/verify-email', validateCsrf, (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
});

router.post('/request-password-reset', validateCsrf, (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
});

router.post('/reset-password', validateCsrf, (req, res) => {
  return res.status(501).json({ error: 'Not implemented' });
});

router.get('/me', (req, res) => {
  return res.json({ authenticated: false });
});

export default router;
