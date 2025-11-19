import * as api from '../../lib/api';
import type { AuditQuery, IAuditLogService } from '../interfaces/audit.interface';
import type { AuditTimelineEntry, AuditSeverity, Page } from '../interfaces/types';

class AuditAdapter implements IAuditLogService {
  async list(params: AuditQuery = {}): Promise<Page<AuditTimelineEntry>> {
    const raw = await api.fetchAuditTimeline(params);
    const items: AuditTimelineEntry[] = Array.isArray(raw?.items)
      ? raw.items.map(normalizeEntry)
      : [];
    return {
      items,
      total: Number(raw?.total ?? items.length),
      page: Number(raw?.page ?? params.page ?? 1),
      pageSize: Number(raw?.pageSize ?? params.pageSize ?? 25),
    };
  }
}

function normalizeEntry(entry: any): AuditTimelineEntry {
  return {
    id: String(entry?.id ?? `audit-${Date.now()}`),
    action: String(entry?.action ?? 'unknown'),
    createdAt: typeof entry?.createdAt === 'string' ? entry.createdAt : new Date().toISOString(),
    description: String(entry?.description ?? entry?.action ?? 'Audit event'),
    severity: normalizeSeverity(entry?.severity),
    actor: {
      id: entry?.actor?.id ?? undefined,
      name: entry?.actor?.name ?? undefined,
      email: entry?.actor?.email ?? undefined,
      initials: entry?.actor?.initials ?? undefined,
    },
    target: entry?.target ?? undefined,
    ipAddress: entry?.ipAddress ?? null,
    userAgent: entry?.userAgent ?? null,
    metadata: entry?.metadata ?? null,
    tags: Array.isArray(entry?.tags) ? entry.tags.map(String) : [],
  };
}

function normalizeSeverity(sev: any): AuditSeverity {
  const value = typeof sev === 'string' ? sev.toLowerCase() : '';
  return isAuditSeverity(value) ? value : 'info';
}

function isAuditSeverity(value: string): value is AuditSeverity {
  return value === 'info' || value === 'warning' || value === 'critical';
}

export const auditAdapter = new AuditAdapter();
export default auditAdapter;
