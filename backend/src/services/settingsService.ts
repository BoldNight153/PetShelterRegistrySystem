import { PrismaClient } from '@prisma/client';
import { ISettingsService } from './interfaces/settingsService.interface';
import { normalizeAuditSettings } from '../types/auditSettings';

export class SettingsService implements ISettingsService {
  private prisma: PrismaClient;
  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  async listSettings(category?: string) {
    const where = category ? { category: String(category) } : {};
    const rows = await this.prisma.setting.findMany({ where, orderBy: [{ category: 'asc' }, { key: 'asc' }] });
    const result: Record<string, Record<string, any>> = {};
    for (const r of rows) {
      result[r.category] ||= {};
      result[r.category][r.key] = r.value;
    }
    if (!category || category === 'audit') {
      result.audit = normalizeAuditSettings(result.audit as Record<string, unknown> | null | undefined);
    }
    return result;
  }

  async upsertSettings(category: string, entries: Array<{ key: string; value: any }>, actorId?: string | null) {
    const writes = [] as any[];
    for (const { key, value } of entries) {
      writes.push(this.prisma.setting.upsert({
        where: { category_key: { category, key } as any },
        create: { category, key, value, updatedBy: actorId || undefined },
        update: { value, updatedBy: actorId || undefined },
      }));
    }
    await this.prisma.$transaction(writes);
  }
}

export default SettingsService;
