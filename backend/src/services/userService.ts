import { PrismaClient } from '@prisma/client';
import { IUserService, UserDetail } from './interfaces/userService.interface';

export class UserService implements IUserService {
  private prisma: PrismaClient;

  constructor(opts?: { prisma: PrismaClient }) {
    this.prisma = opts?.prisma ?? new PrismaClient();
  }
  async searchUsers(q?: string, page = 1, pageSize = 20) {
    const where: any = q
      ? {
          OR: [
            { email: { contains: q, mode: 'insensitive' } },
            { name: { contains: q, mode: 'insensitive' } },
          ],
        }
      : {};
    const [total, items] = await Promise.all([
      this.prisma.user.count({ where }),
      this.prisma.user.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
        select: { id: true, email: true, name: true, roles: { include: { role: true } }, locks: { where: { unlockedAt: null }, orderBy: { lockedAt: 'desc' }, take: 1 } },
      }),
    ]);
    type IUserRow = { id: string; email: string; name: string | null; roles: { role: { name: string } | null }[]; locks: { reason: string; expiresAt: Date | null }[] };
    const users = (items as IUserRow[]).map(u => ({
      id: u.id,
      email: u.email,
      name: u.name,
      roles: u.roles.map(r => r.role?.name).filter((n): n is string => Boolean(n)),
      lock: u.locks && u.locks[0] ? { reason: u.locks[0].reason, until: u.locks[0].expiresAt ? u.locks[0].expiresAt.toISOString() : null } : null,
    }));
    return { items: users, total, page, pageSize };
  }

  async getUser(userId: string): Promise<UserDetail | null> {
  const u = await this.prisma.user.findUnique({ where: { id: userId }, include: { roles: { include: { role: true } }, locks: true } });
    if (!u) return null;
    return {
      id: u.id,
      email: u.email,
      name: u.name,
      roles: u.roles.map(r => r.role?.name).filter((n): n is string => Boolean(n)),
      lock: (() => {
        const found = u.locks && u.locks.find((l: any) => !l.unlockedAt);
        return found ? { reason: found.reason, until: found.expiresAt ? found.expiresAt.toISOString() : null } : null;
      })(),
  createdAt: u.createdAt ? u.createdAt.toISOString() : undefined,
      lastLoginAt: (u as any).lastLoginAt ? (u as any).lastLoginAt?.toISOString() : undefined,
      metadata: (u as any).metadata ?? null,
    };
  }

  async assignRole(userId: string, roleName: string) {
  const role = await this.prisma.role.findUnique({ where: { name: roleName } });
    if (!role) return null;
    const ur = await this.prisma.userRole.upsert({
      where: { userId_roleId: { userId, roleId: role.id } as any },
      update: {},
      create: { userId, roleId: role.id },
    });
    return ur;
  }

  async revokeRole(userId: string, roleName: string) {
    const role = await this.prisma.role.findUnique({ where: { name: roleName } });
    if (!role) return false;
    await this.prisma.userRole.delete({ where: { userId_roleId: { userId, roleId: role.id } as any } });
    return true;
  }

  async lockUser(userId: string, opts: { reason: string; expiresAt?: Date | null; notes?: string | null; actorId?: string | null }) {
    const data: any = { userId, reason: opts.reason, manual: true, lockedAt: new Date(), lockedBy: opts.actorId || null };
    if (opts.expiresAt) data.expiresAt = opts.expiresAt;
    if (opts.notes) data.notes = opts.notes;
    const lock = await this.prisma.userLock.create({ data });
    return lock;
  }

  async unlockUser(userId: string, opts: { actorId?: string | null; notes?: string | null }) {
    const now = new Date();
    await this.prisma.userLock.updateMany({ where: { userId, unlockedAt: null }, data: { unlockedAt: now, unlockedBy: opts.actorId || null, notes: opts.notes || undefined } });
    // revoke refresh tokens
    try { await this.prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: now } }); } catch {}
  }
}
