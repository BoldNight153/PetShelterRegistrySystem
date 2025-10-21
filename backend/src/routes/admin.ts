import express from 'express';
import type { Prisma } from '@prisma/client';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { requireRole } from '../middleware/auth';
import { resetPasswordEmailTemplate, sendMail } from '../lib/email';

const router = express.Router();
// use centralized prisma client
const ERR = { notFound: 'user not found' } as const;

async function logAudit(userId: string | null, action: string, req: any, metadata?: any) {
  try {
    await prisma.auditLog.create({
      data: {
        userId: userId || undefined,
        action,
        ipAddress: req.ip,
        userAgent: req.get('user-agent') || undefined,
        metadata,
      },
    });
  } catch {
    // ignore
  }
}

// Only admins and system_admins can manage roles/permissions
const adminGuard = requireRole('admin', 'system_admin');

// Roles CRUD (minimal: list, create/upsert, delete)
router.get('/roles', adminGuard, async (req, res) => {
  const maybeRoleService = req.container?.resolve?.('roleService') as import('../services/interfaces/roleService.interface').IRoleService | undefined;
  if (maybeRoleService && typeof maybeRoleService.listRoles === 'function') {
    const roles = await maybeRoleService.listRoles();
    return res.json(roles);
  }
  const roles = await prisma.role.findMany({ orderBy: { rank: 'desc' } });
  res.json(roles);
});

const UpsertRoleSchema = z.object({ name: z.string().min(1), rank: z.number().int().min(0).default(0), description: z.string().optional() });
router.post('/roles/upsert', adminGuard, async (req, res) => {
  const parsed = UpsertRoleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { name, rank, description } = parsed.data;
  const maybeRoleService = req.container?.resolve?.('roleService') as import('../services/interfaces/roleService.interface').IRoleService | undefined;
  let role;
  if (maybeRoleService && typeof maybeRoleService.upsertRole === 'function') {
    role = await maybeRoleService.upsertRole(name, rank, description ?? null);
  } else {
    role = await prisma.role.upsert({ where: { name }, update: { rank, description }, create: { name, rank, description } });
  }
  await logAudit(String(req.user?.id ?? '' ) || null, 'admin.roles.upsert', req, { name, rank });
  res.json(role);
});

router.delete('/roles/:name', adminGuard, async (req, res) => {
  const name = req.params.name;
  try {
    const maybeRoleService = req.container?.resolve?.('roleService') as import('../services/interfaces/roleService.interface').IRoleService | undefined;
    if (maybeRoleService && typeof maybeRoleService.deleteRole === 'function') {
      await maybeRoleService.deleteRole(name);
    } else {
      await prisma.role.delete({ where: { name } });
    }
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.roles.delete', req, { name });
    res.status(204).end();
  } catch {
    return res.status(404).json({ error: 'not found' });
  }
});

// Permissions list and grant/revoke to roles
router.get('/permissions', adminGuard, async (req, res) => {
  const maybeRoleService = req.container?.resolve?.('roleService') as import('../services/interfaces/roleService.interface').IRoleService | undefined;
  if (maybeRoleService && typeof maybeRoleService.listPermissions === 'function') {
    const perms = await maybeRoleService.listPermissions();
    return res.json(perms);
  }
  const perms = await prisma.permission.findMany({ orderBy: { name: 'asc' } });
  res.json(perms);
});

const GrantSchema = z.object({ roleName: z.string().min(1), permission: z.string().min(1) });
router.post('/permissions/grant', adminGuard, async (req, res) => {
  const parsed = GrantSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { roleName, permission } = parsed.data;
  const maybeRoleService = req.container?.resolve?.('roleService') as import('../services/interfaces/roleService.interface').IRoleService | undefined;
  if (maybeRoleService && typeof maybeRoleService.grantPermissionToRole === 'function') {
    try {
      await maybeRoleService.grantPermissionToRole(roleName, permission);
      await logAudit(String(req.user?.id ?? '' ) || null, 'admin.permissions.grant', req, { roleName, permission });
      return res.json({ ok: true });
    } catch (e) {
      return res.status(404).json({ error: 'role or permission not found' });
    }
  }
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  const perm = await prisma.permission.findUnique({ where: { name: permission } });
  if (!role || !perm) return res.status(404).json({ error: 'role or permission not found' });
  await prisma.rolePermission.upsert({
    where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } },
    update: {},
    create: { roleId: role.id, permissionId: perm.id },
  });
  await logAudit(String(req.user?.id ?? '' ) || null, 'admin.permissions.grant', req, { roleName, permission });
  res.json({ ok: true });
});

router.post('/permissions/revoke', adminGuard, async (req, res) => {
  const parsed = GrantSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { roleName, permission } = parsed.data;
  const maybeRoleService = req.container?.resolve?.('roleService') as import('../services/interfaces/roleService.interface').IRoleService | undefined;
  if (maybeRoleService && typeof maybeRoleService.revokePermissionFromRole === 'function') {
    try {
      await maybeRoleService.revokePermissionFromRole(roleName, permission);
      await logAudit(String(req.user?.id ?? '' ) || null, 'admin.permissions.revoke', req, { roleName, permission });
      return res.json({ ok: true });
    } catch (e) {
      return res.status(404).json({ error: 'role or permission not found' });
    }
  }
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  const perm = await prisma.permission.findUnique({ where: { name: permission } });
  if (!role || !perm) return res.status(404).json({ error: 'role or permission not found' });
  await prisma.rolePermission.delete({ where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } } });
  await logAudit(String(req.user?.id ?? '' ) || null, 'admin.permissions.revoke', req, { roleName, permission });
  res.json({ ok: true });
});

// Read: list permissions bound to a specific role
router.get('/roles/:name/permissions', adminGuard, async (req, res) => {
  const name = req.params.name;
  const maybeRoleService = req.container?.resolve?.('roleService') as import('../services/interfaces/roleService.interface').IRoleService | undefined;
  if (maybeRoleService && typeof maybeRoleService.listRolePermissions === 'function') {
    const perms = await maybeRoleService.listRolePermissions(name);
    return res.json(perms);
  }
  const role = await prisma.role.findUnique({ where: { name } });
  if (!role) return res.status(404).json({ error: 'role not found' });
  const rp = await prisma.rolePermission.findMany({ where: { roleId: role.id }, include: { permission: true } });
  type PermRow = { permission: { id: string; name: string; description: string | null } };
  const perms = (rp as PermRow[]).map(x => x.permission).sort((a, b) => a.name.localeCompare(b.name));
  res.json(perms);
});

// User role assignments
const AssignRoleSchema = z.object({ userId: z.string().min(1), roleName: z.string().min(1) });
router.post('/users/assign-role', adminGuard, async (req, res) => {
  const parsed = AssignRoleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { userId, roleName } = parsed.data;
  const user = await prisma.user.findUnique({ where: { id: userId } });
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  if (!user || !role) return res.status(404).json({ error: 'user or role not found' });
  // RBAC: only management-level staff and admins can modify roles, and only assign roles lower than their own rank
  const actorId = (req as unknown as Record<string, any>).user?.id as string;
  const actorRoles = await prisma.userRole.findMany({ where: { userId: actorId }, include: { role: true } });
  type ActorRole = { role: { name: string; rank: number } | null };
  const isSystemAdmin = (actorRoles as ActorRole[]).some(ur => ur.role?.name === 'system_admin');
  const actorMaxRank = Math.max(...(actorRoles as ActorRole[]).map(ur => ur.role?.rank ?? 0), 0);
  if (!isSystemAdmin) {
    // management-level staff or higher
    const allowedManagers = ['admin', 'shelter_admin', 'staff_manager'];
    const hasManagerRole = (actorRoles as ActorRole[]).some(ur => ur.role?.name ? allowedManagers.includes(ur.role.name) : false);
    if (!hasManagerRole) return res.status(403).json({ error: 'forbidden' });
    if (role.rank >= actorMaxRank) return res.status(403).json({ error: 'cannot assign same or higher rank' });
  }
  // system_admin can assign any role, including system_admin
  const maybeUserService = req.container?.resolve?.('userService') as import('../services/interfaces/userService.interface').IUserService | undefined;
  if (maybeUserService && typeof maybeUserService.assignRole === 'function') {
    const result = await maybeUserService.assignRole(userId, roleName);
    await logAudit(String(((req as unknown as Record<string, any>).user?.id) ?? '' ) || null, 'admin.users.assign_role', req, { userId, roleName });
    return res.json(result);
  }
  const ur = await prisma.userRole.upsert({
    where: { userId_roleId: { userId, roleId: role.id } },
    update: {},
    create: { userId, roleId: role.id },
  });
  await logAudit(String(((req as unknown as Record<string, any>).user?.id) ?? '' ) || null, 'admin.users.assign_role', req, { userId, roleName });
  res.json(ur);
});

router.post('/users/revoke-role', adminGuard, async (req, res) => {
  const parsed = AssignRoleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { userId, roleName } = parsed.data;
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  if (!role) return res.status(404).json({ error: 'role not found' });
  // Apply same manager/system_admin constraint for revocation
  const actorId = (req as unknown as Record<string, any>).user?.id as string;
  const actorRoles2 = await prisma.userRole.findMany({ where: { userId: actorId }, include: { role: true } });
  type ActorRole2 = { role: { name: string; rank: number } | null };
  const isSystemAdmin2 = (actorRoles2 as ActorRole2[]).some(ur => ur.role?.name === 'system_admin');
  const actorMaxRank2 = Math.max(...(actorRoles2 as ActorRole2[]).map(ur => ur.role?.rank ?? 0), 0);
  if (!isSystemAdmin2) {
    const allowedManagers = ['admin', 'shelter_admin', 'staff_manager'];
    const hasManagerRole = (actorRoles2 as ActorRole2[]).some(ur => ur.role?.name ? allowedManagers.includes(ur.role.name) : false);
    if (!hasManagerRole) return res.status(403).json({ error: 'forbidden' });
    if (role.rank >= actorMaxRank2) return res.status(403).json({ error: 'cannot revoke same or higher rank' });
  }
  const maybeUserService = req.container?.resolve?.('userService') as import('../services/interfaces/userService.interface').IUserService | undefined;
  if (maybeUserService && typeof maybeUserService.revokeRole === 'function') {
    const ok = await maybeUserService.revokeRole(userId, roleName);
    await logAudit(String(((req as unknown as Record<string, any>).user?.id) ?? '' ) || null, 'admin.users.revoke_role', req, { userId, roleName });
    return res.json({ ok });
  }
  await prisma.userRole.delete({ where: { userId_roleId: { userId, roleId: role.id } } });
  await logAudit(String(((req as unknown as Record<string, any>).user?.id) ?? '' ) || null, 'admin.users.revoke_role', req, { userId, roleName });
  res.json({ ok: true });
});

// Read: list roles assigned to a user
router.get('/users/:userId/roles', adminGuard, async (req, res) => {
  const { userId } = req.params as { userId: string };
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: ERR.notFound });
  const urs = await prisma.userRole.findMany({ where: { userId }, include: { role: true } });
  type UR = { role: { id: string; name: string; rank: number } | null };
  const roles = (urs as UR[]).map(ur => ur.role).filter((r): r is NonNullable<UR['role']> => Boolean(r)).sort((a, b) => (b.rank ?? 0) - (a.rank ?? 0));
  res.json(roles);
});

// Read: search/list users (id, email, name, roles)
router.get('/users', adminGuard, async (req, res) => {
  // Prefer to use injected userService when available (via awilix scopePerRequest)
  try {
    // normalize params
  const rawQ = req.query.q;
  const q = typeof rawQ === 'string' ? rawQ.trim() : String(rawQ ?? '').trim();
    const page = Math.max(1, Number(req.query.page ?? 1));
    const pageSize = Math.min(100, Math.max(1, Number(req.query.pageSize ?? 20)));
  const maybeUserService = req.container?.resolve?.('userService') as import('../services/interfaces/userService.interface').IUserService | undefined;
    if (maybeUserService && typeof maybeUserService.searchUsers === 'function') {
      const result = await maybeUserService.searchUsers(q || undefined, page, pageSize);
      return res.json(result);
    }
    // Fallback to previous logic if DI not available (keeps behavior stable during migration)
    const where: any = q
      ? {
          OR: [
            { email: { contains: q, mode: 'insensitive' } },
            { name: { contains: q, mode: 'insensitive' } },
          ],
        }
      : {};
    const [total, items] = await Promise.all([
      prisma.user.count({ where }),
      prisma.user.findMany({
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
      lock: u.locks && u.locks[0] ? { reason: u.locks[0].reason, until: u.locks[0].expiresAt } : null,
    }));
    res.json({ items: users, total, page, pageSize });
  } catch (err) {
  try { (req as unknown as Record<string, any>).log?.error({ err }, 'user listing failed'); } catch {}
    res.status(500).json({ error: 'Failed to list users' });
  }
});

// Manual lock a user (staff_manager and higher)
const staffGuard = requireRole('staff_manager', 'shelter_admin', 'admin', 'system_admin');
router.post('/users/lock', staffGuard, async (req: any, res) => {
  const { userId, reason, expiresAt, notes } = req.body || {};
  if (!userId || !reason) return res.status(400).json({ error: 'userId and reason are required' });
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: ERR.notFound });
  const data: any = { userId, reason: String(reason), manual: true, lockedAt: new Date(), lockedBy: req.user?.id || null };
  if (expiresAt) data.expiresAt = new Date(String(expiresAt));
  if (notes) data.notes = String(notes);
  const maybeUserService = req.container?.resolve?.('userService') as import('../services/interfaces/userService.interface').IUserService | undefined;
  if (maybeUserService && typeof maybeUserService.lockUser === 'function') {
    const lock = await maybeUserService.lockUser(userId, { reason: String(reason), expiresAt: data.expiresAt ?? null, notes: data.notes ?? null, actorId: req.user?.id || null });
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.users.lock', req, { userId, reason, expiresAt: data.expiresAt ?? null });
    return res.json({ ok: true, lock });
  }
  const lock = await prisma.userLock.create({ data });
  await logAudit(String(req.user?.id ?? '' ) || null, 'admin.users.lock', req, { userId, reason, expiresAt: data.expiresAt ?? null });
  res.json({ ok: true, lock });
});

// Manual unlock a user — sends password reset email and revokes sessions
router.post('/users/unlock', staffGuard, async (req: any, res) => {
  const { userId, unlockReason } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId is required' });
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: 'user not found' });
  const maybeUserService = (req as unknown as Record<string, any>).container?.resolve?.('userService') as any | undefined;
  if (maybeUserService && typeof maybeUserService.unlockUser === 'function') {
    await maybeUserService.unlockUser(userId, { actorId: req.user?.id || null, notes: unlockReason || undefined });
    // send password reset email still handled by service or fallback below
    try {
      const appOrigin = process.env.APP_ORIGIN || 'http://localhost:5173';
      const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
      const ttl = Number(process.env.PASSWORD_RESET_TTL_MIN || 60);
      const expiresAt = new Date(Date.now() + ttl * 60 * 1000);
      await prisma.verificationToken.create({ data: { identifier: user.email, token, type: 'password_reset', expiresAt } });
      const resetUrl = `${appOrigin}/reset-password?token=${encodeURIComponent(token)}`;
      const tpl = resetPasswordEmailTemplate({ resetUrl });
      await sendMail({ to: user.email, subject: 'Reset your password', text: tpl.text, html: tpl.html });
    } catch {}
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.users.unlock', req, { userId });
    return res.json({ ok: true });
  }
  const now = new Date();
  await prisma.userLock.updateMany({ where: { userId, unlockedAt: null }, data: { unlockedAt: now, unlockedBy: req.user?.id || null, notes: unlockReason || undefined } });
  // Send reset email (reuse existing template)
  try {
    const appOrigin = process.env.APP_ORIGIN || 'http://localhost:5173';
    const token = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    const ttl = Number(process.env.PASSWORD_RESET_TTL_MIN || 60);
    const expiresAt = new Date(Date.now() + ttl * 60 * 1000);
    await prisma.verificationToken.create({ data: { identifier: user.email, token, type: 'password_reset', expiresAt } });
    const resetUrl = `${appOrigin}/reset-password?token=${encodeURIComponent(token)}`;
    const tpl = resetPasswordEmailTemplate({ resetUrl });
    await sendMail({ to: user.email, subject: 'Reset your password', text: tpl.text, html: tpl.html });
  } catch {}
  // Revoke sessions
  try { await prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: now } }); } catch {}
  await logAudit(String(req.user?.id ?? '' ) || null, 'admin.users.unlock', req, { userId });
  res.json({ ok: true });
});

export default router;

// ----------------------
// Settings management
// ----------------------
// Place after default export so existing imports continue to work; router remains same instance

const settingsGuard = requireRole('system_admin');

// List all settings (optionally filter by category)
router.get('/settings', settingsGuard, async (req: any, res) => {
  const { category } = req.query as { category?: string };
  const maybeSettings = req.container?.resolve?.('settingsService') as import('../services/interfaces/settingsService.interface').ISettingsService | undefined;
  if (maybeSettings && typeof maybeSettings.listSettings === 'function') {
    const settings = await maybeSettings.listSettings(category);
    return res.json({ settings });
  }
  const where = category ? { category: String(category) } : {};
  const rows = await prisma.setting.findMany({ where, orderBy: [{ category: 'asc' }, { key: 'asc' }] });
  // Shape into { [category]: { key: value } }
  const result: Record<string, Record<string, any>> = {};
  for (const r of rows) {
    result[r.category] ||= {};
    result[r.category][r.key] = r.value;
  }
  res.json({ settings: result });
});

// Upsert settings for a category; body: { category: string, entries: { key: string, value: any }[] }
const UpsertSettingsSchema = z.object({
  category: z.string().min(1),
  entries: z.array(z.object({ key: z.string().min(1), value: z.any() })).min(1),
});

router.put('/settings', settingsGuard, async (req: any, res) => {
  const parsed = UpsertSettingsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { category, entries } = parsed.data;
  const actorId = req.user?.id || null;
  const maybeSettings = req.container?.resolve?.('settingsService') as any | undefined;
  if (maybeSettings && typeof maybeSettings.upsertSettings === 'function') {
    await maybeSettings.upsertSettings(category, entries, actorId);
    await logAudit((typeof actorId === 'string' ? actorId : null), 'admin.settings.upsert', req, { category, keys: entries.map((e: { key: string }) => e.key) });
    return res.json({ ok: true });
  }
  const writes: Array<Prisma.PrismaPromise<any>> = [];
  for (const { key, value } of entries) {
    writes.push(prisma.setting.upsert({
      where: { category_key: { category, key } },
      create: { category, key, value, updatedBy: actorId || undefined },
      update: { value, updatedBy: actorId || undefined },
    }));
  }
  await prisma.$transaction(writes);
  await logAudit((typeof actorId === 'string' ? actorId : null), 'admin.settings.upsert', req, { category, keys: entries.map((e: { key: string }) => e.key) });
  res.json({ ok: true });
});

// ----------------------
// Audit Logs listing
// ----------------------

const auditGuard = requireRole('admin', 'system_admin');
router.get('/audit', auditGuard, async (req: any, res) => {
  const maybeAudit = req.container?.resolve?.('auditService') as import('../services/interfaces/auditService.interface').IAuditService | undefined;
  if (maybeAudit && typeof maybeAudit.listAudit === 'function') {
    const params = {
      q: (req.query.q ?? '').toString().trim(),
      action: (req.query.action ?? '').toString().trim(),
      userId: (req.query.userId ?? '').toString().trim(),
      from: req.query.from ? new Date(String(req.query.from)) : null,
      to: req.query.to ? new Date(String(req.query.to)) : null,
      page: Math.max(1, Number(req.query.page ?? 1)),
      pageSize: Math.min(200, Math.max(1, Number(req.query.pageSize ?? 25))),
    };
    const result = await maybeAudit.listAudit(params);
    return res.json(result);
  }
  const page = Math.max(1, Number(req.query.page ?? 1));
  const pageSize = Math.min(200, Math.max(1, Number(req.query.pageSize ?? 25)));
  const q = (req.query.q ?? '').toString().trim();
  const action = (req.query.action ?? '').toString().trim();
  const userId = (req.query.userId ?? '').toString().trim();
  const from = req.query.from ? new Date(String(req.query.from)) : null;
  const to = req.query.to ? new Date(String(req.query.to)) : null;

  const where: any = {};
  if (action) where.action = { contains: action };
  if (userId) where.userId = userId;
  if (from || to) where.createdAt = { gte: from ?? undefined, lte: to ?? undefined };
  if (q) {
    where.OR = [
      { ipAddress: { contains: q } },
      { userAgent: { contains: q } },
      { action: { contains: q } },
    ];
  }

  const [total, items] = await Promise.all([
    prisma.auditLog.count({ where }),
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * pageSize,
      take: pageSize,
    }),
  ]);

  res.json({ items, total, page, pageSize });
});
