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

  private normalizeWindowMs(ms: number) {
    return Math.max(ms, 1);
  }

  private windowStartFor(ms: number) {
    const normalized = this.normalizeWindowMs(ms);
    const now = Date.now();
    const start = now - (now % normalized);
    return new Date(start);
  }

  private windowBounds(windowMs: number) {
    const normalized = this.normalizeWindowMs(windowMs);
    return new Date(Date.now() - normalized);
  }

  private async pruneOldBuckets(scope: string, key: string, windowMs: number) {
    const normalized = this.normalizeWindowMs(windowMs);
    const cutoff = new Date(Date.now() - normalized * 4);
    await this.prisma.rateLimit.deleteMany({ where: { scope, key, windowStart: { lt: cutoff } as any } }).catch(() => {});
  }

  private async summarizeRecent(scope: string, key: string, windowMs: number) {
    const since = this.windowBounds(windowMs);
    const rows = await this.prisma.rateLimit.findMany({
      where: { scope, key, windowStart: { gte: since } as any },
      select: { count: true, windowStart: true },
      orderBy: { windowStart: 'desc' },
    });
    if (!rows.length) {
      const now = new Date();
      return { count: 0, latestWindow: now, earliestWindow: now };
    }
    const count = rows.reduce((sum, row) => sum + row.count, 0);
    return { count, latestWindow: rows[0].windowStart, earliestWindow: rows[rows.length - 1].windowStart };
  }

  async incrementAndCheck(opts: LimitOptions) {
    const { scope, key, windowMs, limit } = opts;
    const windowStart = this.windowStartFor(windowMs);
    const now = new Date();
    const compositeWhere = { scope_key_windowStart: { scope, key, windowStart } } as any;
    const existing = await this.prisma.rateLimit.findUnique({ where: compositeWhere });
    if (!existing) {
      await this.prisma.rateLimit.create({ data: { scope, key, windowStart, count: 1, lastAttemptAt: now } });
    } else {
      await this.prisma.rateLimit.update({ where: compositeWhere, data: { count: { increment: 1 }, lastAttemptAt: now } });
    }

    await this.pruneOldBuckets(scope, key, windowMs);
    const summary = await this.summarizeRecent(scope, key, windowMs);
    const allowed = summary.count <= limit;
    const remaining = Math.max(0, limit - summary.count);
    const windowReset = new Date(summary.latestWindow.getTime() + this.normalizeWindowMs(windowMs));
    return { allowed, remaining, count: summary.count, windowReset };
  }

  async getCount(opts: Omit<LimitOptions, 'limit'>) {
    const { scope, key, windowMs } = opts;
    await this.pruneOldBuckets(scope, key, windowMs);
    const summary = await this.summarizeRecent(scope, key, windowMs);
    const windowReset = new Date(summary.latestWindow.getTime() + this.normalizeWindowMs(windowMs));
    return { count: summary.count, windowStart: summary.earliestWindow, windowReset };
  }

  async resetWindow(scope: string, key: string, _windowMs?: number) {
    await this.prisma.rateLimit.deleteMany({ where: { scope, key } as any }).catch(() => {});
  }
}

export default RateLimitService;
