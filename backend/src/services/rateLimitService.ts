import { PrismaClient } from '@prisma/client';
import { prismaClient as sharedPrisma } from '../prisma/client';
import type { IRateLimitService } from './interfaces/rateLimitService.interface';

export type LimitOptions = {
  scope: string;
  key: string;
  windowMs: number;
  limit: number;
};

export class RateLimitService implements IRateLimitService {
  constructor(public prisma: PrismaClient) {
    // Some tests mock `@prisma/client` and return a PrismaClient with a
    // limited shape (missing the generated model helpers like `rateLimit`).
    // In that case we should fall back to the real shared Prisma client so
    // the service can operate against the test DB schema. This keeps the
    // migration to a DI-provided client safe while being defensive in tests.
    //
    // We check for the existence of the model accessor and a likely method
    // to detect a valid Prisma model API surface.
    const mayHaveModel = (this.prisma as any)?.rateLimit;
    if (!mayHaveModel || typeof mayHaveModel.findUnique !== 'function') {
      this.prisma = sharedPrisma as unknown as PrismaClient;
    }
  }

  private windowStartFor(ms: number) {
    const now = Date.now();
    const start = now - (now % ms);
    return new Date(start);
  }

  async incrementAndCheck(opts: LimitOptions) {
    const { scope, key, windowMs, limit } = opts;
    const windowStart = this.windowStartFor(windowMs);
    const now = new Date();
    const existing = await this.prisma.rateLimit.findUnique({ where: { scope_key_windowStart: { scope, key, windowStart } as any } });
    let count = 0;
    if (!existing) {
      await this.prisma.rateLimit.create({ data: { scope, key, windowStart, count: 1, lastAttemptAt: now } });
      count = 1;
    } else {
      const updated = await this.prisma.rateLimit.update({ where: { scope_key_windowStart: { scope, key, windowStart } as any }, data: { count: { increment: 1 }, lastAttemptAt: now } });
      count = updated.count;
    }
    const allowed = count <= limit;
    const remaining = Math.max(0, limit - count);
    const windowReset = new Date(windowStart.getTime() + windowMs);
    return { allowed, remaining, count, windowReset };
  }

  async getCount(opts: Omit<LimitOptions, 'limit'>) {
    const { scope, key, windowMs } = opts;
    const windowStart = this.windowStartFor(windowMs);
    const row = await this.prisma.rateLimit.findUnique({ where: { scope_key_windowStart: { scope, key, windowStart } as any } });
    const count = row?.count ?? 0;
    return { count, windowStart, windowReset: new Date(windowStart.getTime() + windowMs) };
  }

  async resetWindow(scope: string, key: string, windowMs: number) {
    const windowStart = this.windowStartFor(windowMs);
    try { await this.prisma.rateLimit.delete({ where: { scope_key_windowStart: { scope, key, windowStart } as any } }); } catch {}
  }
}

export default RateLimitService;
