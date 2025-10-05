import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const prisma: any = new PrismaClient();

export type AuthUser = {
  id: string;
  roles: string[];
  permissions: string[];
};

function getTokenFromRequest(req: Request): string | undefined {
  const cookieToken = (req as any).cookies?.accessToken as string | undefined;
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
    const payload = jwt.verify(token, secret) as any;
    const userId = payload?.sub as string | undefined;
    if (!userId) return next();

    // fetch user roles
    const userRoles = await prisma.userRole.findMany({
      where: { userId },
      include: { role: true },
    });
    const roles = userRoles.map((ur: any) => ur.role?.name).filter(Boolean) as string[];

    // fetch permissions via role->rolePermission->permission
    let permissions: string[] = [];
    if (roles.length) {
      const rp = await prisma.rolePermission.findMany({
        where: { role: { name: { in: roles } } },
        include: { permission: true },
      });
      permissions = rp.map((x: any) => x.permission?.name).filter(Boolean) as string[];
    }

    (req as any).user = { id: userId, roles, permissions } as AuthUser;
    return next();
  } catch (_err) {
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
    const user = (req as any).user as AuthUser | undefined;
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    if (!user.roles.some(r => allowed.includes(r))) {
      // Lightweight debug to help tests diagnose RBAC issues
      if (process.env.NODE_ENV === 'test') {
        try {
          (req as any).log?.warn?.({ roles: user.roles, allowed }, 'RBAC forbid');
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
    const user = (req as any).user as AuthUser | undefined;
    if (!user) return res.status(401).json({ error: 'unauthorized' });
    if (!perms.every(p => user.permissions.includes(p))) return res.status(403).json({ error: 'forbidden' });
    return next();
  };
}
