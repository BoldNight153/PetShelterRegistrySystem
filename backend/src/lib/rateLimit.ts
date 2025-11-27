import { prismaClient as prisma } from '../prisma/client';

// use centralized prisma client

export type LimitOptions = {
  scope: string; // e.g., 'auth_login_ip' or 'auth_login_user_fail'
  key: string;   // ip or email
  windowMs: number;
  limit: number;
};

function windowStartFor(ms: number) {
  const now = Date.now();
  const start = now - (now % Math.max(ms, 1));
  return new Date(start);
}

function windowBounds(windowMs: number) {
  const now = Date.now();
  return new Date(now - Math.max(windowMs, 1));
}

async function pruneOldBuckets(scope: string, key: string, windowMs: number) {
  const cutoff = new Date(Date.now() - Math.max(windowMs, 1) * 4);
  await prisma.rateLimit.deleteMany({ where: { scope, key, lastAttemptAt: { lt: cutoff } } }).catch(() => {});
}

async function summarizeRecent(scope: string, key: string, windowMs: number) {
  const since = windowBounds(windowMs);
  const rows = await prisma.rateLimit.findMany({
    where: { scope, key, lastAttemptAt: { gte: since } },
    select: { count: true, windowStart: true, lastAttemptAt: true },
    orderBy: { lastAttemptAt: 'desc' },
  });
  if (!rows.length) {
    const now = new Date();
    return { count: 0, latestWindow: now, earliestWindow: now };
  }
  const count = rows.reduce((sum, row) => sum + row.count, 0);
  const latestWindow = rows[0].lastAttemptAt ?? rows[0].windowStart;
  const earliestWindow = rows[rows.length - 1].lastAttemptAt ?? rows[rows.length - 1].windowStart;
  return { count, latestWindow, earliestWindow };
}

export async function incrementAndCheck(opts: LimitOptions): Promise<{ allowed: boolean; remaining: number; count: number; windowReset: Date }>
{
  const { scope, key, windowMs, limit } = opts;
  const windowStart = windowStartFor(windowMs);
  const now = new Date();
  const existing = await prisma.rateLimit.findUnique({ where: { scope_key_windowStart: { scope, key, windowStart } } });
  if (!existing) {
    await prisma.rateLimit.create({ data: { scope, key, windowStart, count: 1, lastAttemptAt: now } });
  } else {
    await prisma.rateLimit.update({
      where: { scope_key_windowStart: { scope, key, windowStart } },
      data: { count: { increment: 1 }, lastAttemptAt: now },
    });
  }

  await pruneOldBuckets(scope, key, windowMs);
  const summary = await summarizeRecent(scope, key, windowMs);
  const allowed = summary.count <= limit;
  const remaining = Math.max(0, limit - summary.count);
  const windowResetBase = summary.latestWindow ?? windowStart;
  const windowReset = new Date(windowResetBase.getTime() + windowMs);
  return { allowed, remaining, count: summary.count, windowReset };
}

// Utility for lockouts: track consecutive failures per key in a longer window
export async function getCount(opts: Omit<LimitOptions, 'limit'>): Promise<{ count: number; windowStart: Date; windowReset: Date }>
{
  const { scope, key, windowMs } = opts;
  await pruneOldBuckets(scope, key, windowMs);
  const summary = await summarizeRecent(scope, key, windowMs);
  const windowStart = summary.earliestWindow ?? new Date();
  const windowReset = new Date((summary.latestWindow ?? new Date()).getTime() + windowMs);
  return { count: summary.count, windowStart, windowReset };
}

export async function resetWindow(scope: string, key: string, _windowMs?: number) {
  await prisma.rateLimit.deleteMany({ where: { scope, key } }).catch(() => {});
}
