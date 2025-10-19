import { Prisma } from '@prisma/client';

export interface AuditRow {
  id: string;
  userId?: string | null;
  action: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Prisma.JsonValue;
  createdAt: Date;
}

export interface IAuditService {
  listAudit(params: { q?: string; action?: string; userId?: string; from?: Date | null; to?: Date | null; page?: number; pageSize?: number }): Promise<{ items: AuditRow[]; total: number; page: number; pageSize: number }>;
}

export default IAuditService;
