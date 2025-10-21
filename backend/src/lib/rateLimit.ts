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
  const start = now - (now % ms);
  return new Date(start);
}

export async function incrementAndCheck(opts: LimitOptions): Promise<{ allowed: boolean; remaining: number; count: number; windowReset: Date }>
{
  const { scope, key, windowMs, limit } = opts;
  const windowStart = windowStartFor(windowMs);
  const now = new Date();
  const existing = await prisma.rateLimit.findUnique({ where: { scope_key_windowStart: { scope, key, windowStart } } });
  let count = 0;
  if (!existing) {
    await prisma.rateLimit.create({ data: { scope, key, windowStart, count: 1, lastAttemptAt: now } });
    count = 1;
  } else {
    const updated = await prisma.rateLimit.update({
      where: { scope_key_windowStart: { scope, key, windowStart } },
      data: { count: { increment: 1 }, lastAttemptAt: now },
    });
    count = updated.count;
  }
  const allowed = count <= limit;
  const remaining = Math.max(0, limit - count);
  const windowReset = new Date(windowStart.getTime() + windowMs);
  return { allowed, remaining, count, windowReset };
}

// Utility for lockouts: track consecutive failures per key in a longer window
export async function getCount(opts: Omit<LimitOptions, 'limit'>): Promise<{ count: number; windowStart: Date; windowReset: Date }>
{
  const { scope, key, windowMs } = opts;
  const windowStart = windowStartFor(windowMs);
  const row = await prisma.rateLimit.findUnique({ where: { scope_key_windowStart: { scope, key, windowStart } } });
  const count = row?.count ?? 0;
  return { count, windowStart, windowReset: new Date(windowStart.getTime() + windowMs) };
}

export async function resetWindow(scope: string, key: string, windowMs: number) {
  const windowStart = windowStartFor(windowMs);
  try {
    await prisma.rateLimit.delete({ where: { scope_key_windowStart: { scope, key, windowStart } } });
  } catch {}
}
