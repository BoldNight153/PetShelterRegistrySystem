import type { Prisma } from '@prisma/client';

export type AuditSeverity = 'info' | 'warning' | 'critical';

export type AuditActor = {
  id?: string | null;
  name?: string | null;
  email?: string | null;
  initials?: string | null;
};

export type AuditTarget = {
  type: string;
  id?: string | null;
  label?: string | null;
};

export interface AuditTimelineEntry {
  id: string;
  action: string;
  createdAt: string;
  description: string;
  severity: AuditSeverity;
  actor: AuditActor;
  target?: AuditTarget;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Prisma.JsonValue | null;
  tags: string[];
}

export type AuditTimelineStats = {
  severity: Record<AuditSeverity, number>;
  uniqueActors: number;
  uniqueActions: number;
  range: {
    from: string | null;
    to: string | null;
  };
};

export interface AuditListParams {
  q?: string;
  action?: string;
  userId?: string;
  from?: Date | null;
  to?: Date | null;
  page?: number;
  pageSize?: number;
}

export interface AuditTimelineResponse {
  items: AuditTimelineEntry[];
  total: number;
  page: number;
  pageSize: number;
  stats: AuditTimelineStats;
}

export interface IAuditService {
  listAudit(params: AuditListParams): Promise<AuditTimelineResponse>;
}

export default IAuditService;
