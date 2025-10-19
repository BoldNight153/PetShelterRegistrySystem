import type { UserSummaryWithLock, UserDetail } from '../../lib/api';

export interface IUserService {
  searchUsers(q?: string, page?: number, pageSize?: number): Promise<{ items: UserSummaryWithLock[]; total: number; page: number; pageSize: number }>;
  getUser(userId: string): Promise<UserDetail>;
  assignUserRole(userId: string, roleName: string): Promise<unknown>;
  revokeUserRole(userId: string, roleName: string): Promise<unknown>;
  lockUser(userId: string, reason: string, expiresAt?: string | null, notes?: string): Promise<unknown>;
  unlockUser(userId: string, unlockReason?: string): Promise<unknown>;
  listSessions?(userId: string): Promise<Array<{ id: string; createdAt?: string; ip?: string; userAgent?: string }>>;
}
