import { Prisma, PrismaClient } from '@prisma/client';
import { ISettingsService, ListSettingsOptions } from './interfaces/settingsService.interface';
import { normalizeAuditSettings } from '../types/auditSettings';
import { DEFAULT_AUTH_SETTINGS, normalizeAuthSettingEntry, normalizeAuthSettings } from '../types/authSettings';

export class SettingsService implements ISettingsService {
  private prisma: PrismaClient;
  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  private async resolveAuthenticatorIdBuckets() {
    const rows = await this.prisma.authenticatorCatalog.findMany({
      orderBy: { sortOrder: 'asc' },
      select: { id: true, isArchived: true },
    });
    if (!rows.length) {
      const defaults = [...DEFAULT_AUTH_SETTINGS.authenticators];
      return { allowedIds: defaults, fallbackIds: defaults };
    }
    const allowedIds = rows.map(entry => entry.id);
    const activeIds = rows.filter(entry => !entry.isArchived).map(entry => entry.id);
    const fallbackIds = activeIds.length ? activeIds : allowedIds;
    return { allowedIds, fallbackIds };
  }

  async listSettings(category?: string, options?: ListSettingsOptions) {
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
    if (!category || category === 'auth') {
      const { allowedIds, fallbackIds } = await this.resolveAuthenticatorIdBuckets();
      result.auth = normalizeAuthSettings(result.auth as Record<string, unknown> | null | undefined, {
        allowedAuthenticatorIds: allowedIds,
        fallbackAuthenticators: fallbackIds,
        preserveUnknown: Boolean(options?.preserveUnknownAuth),
      });
    }
    return result;
  }

  async upsertSettings(category: string, entries: Array<{ key: string; value: any }>, actorId?: string | null) {
    let allowedIds: string[] | undefined;
    let fallbackIds: string[] | undefined;
    if (category === 'auth') {
      const buckets = await this.resolveAuthenticatorIdBuckets();
      allowedIds = buckets.allowedIds;
      fallbackIds = buckets.fallbackIds;
    }
    const writes = [] as any[];
    for (const { key, value } of entries) {
      const resolvedValue = category === 'auth'
        ? normalizeAuthSettingEntry(key, value, {
            allowedAuthenticatorIds: allowedIds,
            fallbackAuthenticators: fallbackIds ?? allowedIds,
          })
        : value;
      const normalizedValue = resolvedValue as Prisma.InputJsonValue;
      writes.push(this.prisma.setting.upsert({
        where: { category_key: { category, key } as any },
        create: { category, key, value: normalizedValue, updatedBy: actorId || undefined },
        update: { value: normalizedValue, updatedBy: actorId || undefined },
      }));
    }
    await this.prisma.$transaction(writes);
  }
}

export default SettingsService;
