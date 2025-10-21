import { PrismaClient } from '@prisma/client';
import { IAuditService } from './interfaces/auditService.interface';

export class AuditService implements IAuditService {
  private prisma: PrismaClient;
  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  async listAudit(params: { q?: string; action?: string; userId?: string; from?: Date | null; to?: Date | null; page?: number; pageSize?: number }) {
    const page = Math.max(1, Number(params.page ?? 1));
    const pageSize = Math.min(200, Math.max(1, Number(params.pageSize ?? 25)));
    const q = (params.q ?? '').toString().trim();
    const action = (params.action ?? '').toString().trim();
    const userId = (params.userId ?? '').toString().trim();
    const from = params.from ?? null;
    const to = params.to ?? null;

    const where: any = {};
    if (action) where.action = { contains: action };
    if (userId) where.userId = userId;
    if (from || to) where.createdAt = { gte: from ?? undefined, lte: to ?? undefined };
    if (q) {
      where.OR = [
        { ipAddress: { contains: q } },
        { userAgent: { contains: q } },
        { action: { contains: q } },
      ];
    }

    const [total, items] = await Promise.all([
      this.prisma.auditLog.count({ where }),
      this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
    ]);

    return { items, total, page, pageSize };
  }
}

export default AuditService;
