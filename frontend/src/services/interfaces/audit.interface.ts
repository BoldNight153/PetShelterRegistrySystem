import type { Page, AuditTimelineEntry } from './types';

export type AuditQuery = {
  q?: string;
  action?: string;
  userId?: string;
  from?: string;
  to?: string;
  page?: number;
  pageSize?: number;
};

export interface IAuditLogService {
  list(params?: AuditQuery): Promise<Page<AuditTimelineEntry>>;
}
