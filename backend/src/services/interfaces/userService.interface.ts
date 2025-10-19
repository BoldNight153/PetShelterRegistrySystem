import type { Prisma, UserRole, UserLock } from '@prisma/client';

export type UserDetail = {
  id: string;
  email: string;
  name?: string | null;
  roles: string[];
  lock?: { reason: string; until: string | null } | null;
  createdAt?: string;
  lastLoginAt?: string | undefined;
  metadata?: Prisma.JsonValue | null;
};

export interface IUserService {
  searchUsers(q?: string, page?: number, pageSize?: number): Promise<{ items: UserDetail[]; total: number; page: number; pageSize: number }>;
  getUser(userId: string): Promise<UserDetail | null>;
  assignRole(userId: string, roleName: string): Promise<UserRole | null>;
  revokeRole(userId: string, roleName: string): Promise<boolean>;
  lockUser(userId: string, opts: { reason: string; expiresAt?: Date | null; notes?: string | null; actorId?: string | null }): Promise<UserLock>;
  unlockUser(userId: string, opts: { actorId?: string | null; notes?: string | null }): Promise<void>;
}

export default IUserService;

