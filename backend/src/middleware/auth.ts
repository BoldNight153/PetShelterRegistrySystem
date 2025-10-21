import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { prismaClient as prisma } from '../prisma/client';
import type { RoleService } from '../services/roleService';
import type { UserService } from '../services/userService';

// centralized prisma client

export type AuthUser = {
  id: string;
  roles: string[];
  permissions: string[];
};

function getTokenFromRequest(req: Request): string | undefined {
  const cookieToken = (req as unknown as Record<string, any>).cookies?.accessToken as string | undefined;
  const auth = req.header('authorization') || req.header('Authorization');
  const headerToken = auth?.startsWith('Bearer ')
    ? auth.slice('Bearer '.length)
    : undefined;
  return cookieToken || headerToken;
}

export async function parseAuth(req: Request, _res: Response, next: NextFunction) {
  try {
    const token = getTokenFromRequest(req);
    if (!token) return next();
    const secret = process.env.JWT_ACCESS_SECRET || 'dev-access-secret';
    const payload = jwt.verify(token, secret) as Record<string, any> | null;
    const userId = payload?.sub as string | undefined;
    if (!userId) return next();
    // Prefer role/user service from DI for lookups to enable test/mockability
    let roles: string[] = [];
    let permissions: string[] = [];
    try {
      const maybeRoleSvc = (req as any).container?.resolve?.('roleService') as RoleService | undefined | null;
      const maybeUserSvc = (req as any).container?.resolve?.('userService') as UserService | undefined | null;
      if (maybeUserSvc) {
        const u = await maybeUserSvc.getUser(userId);
        roles = u?.roles ?? [];
      } else {
        const userRoles = await prisma.userRole.findMany({ where: { userId }, include: { role: true } });
        roles = userRoles.map((ur: any) => ur.role?.name).filter(Boolean) as string[];
      }
      if (maybeRoleSvc && roles.length) {
        // roleService can list permissions, but for efficiency we'll query rolePermission via prisma for now
        const rp = await prisma.rolePermission.findMany({ where: { role: { name: { in: roles } } }, include: { permission: true } });
        permissions = rp.map((x: any) => x.permission?.name).filter(Boolean) as string[];
      } else if (roles.length) {
        const rp = await prisma.rolePermission.findMany({ where: { role: { name: { in: roles } } }, include: { permission: true } });
        permissions = rp.map((x: any) => x.permission?.name).filter(Boolean) as string[];
      }
    } catch {
      // best-effort; leave roles/permissions empty on error
    }

    (req as unknown as Record<string, any>).user = { id: userId, roles, permissions } as AuthUser;
    return next();
  } catch {
    // swallow errors and continue unauthenticated
    return next();
  }
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!(req as any).user) return res.status(401).json({ error: 'unauthorized' });
  return next();
}

export function requireRole(...allowed: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as unknown as Record<string, any>).user as AuthUser | undefined;
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    if (!user.roles.some(r => allowed.includes(r))) {
      // Lightweight debug to help tests diagnose RBAC issues
      if (process.env.NODE_ENV === 'test') {
        try {
          (req as unknown as Record<string, any>).log?.warn?.({ roles: user.roles, allowed }, 'RBAC forbid');
        } catch (_) {
          // no-op
        }
      }
      return res.status(403).json({ error: 'forbidden' });
    }
    return next();
  };
}

export function requirePermission(...perms: string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as unknown as Record<string, any>).user as AuthUser | undefined;
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    if (!perms.every(p => user.permissions.includes(p))) return res.status(403).json({ error: 'forbidden' });
    return next();
  };
}
