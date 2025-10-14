import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { requireRole } from '../middleware/auth';

const router = express.Router();
const prisma: any = new PrismaClient();

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
  } catch (_) {
    // ignore
  }
}

// Only admins and system_admins can manage roles/permissions
const adminGuard = requireRole('admin', 'system_admin');

// Roles CRUD (minimal: list, create/upsert, delete)
router.get('/roles', adminGuard, async (_req, res) => {
  const roles = await prisma.role.findMany({ orderBy: { rank: 'desc' } });
  res.json(roles);
});

const UpsertRoleSchema = z.object({ name: z.string().min(1), rank: z.number().int().min(0).default(0), description: z.string().optional() });
router.post('/roles/upsert', adminGuard, async (req, res) => {
  const parsed = UpsertRoleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { name, rank, description } = parsed.data;
  const role = await prisma.role.upsert({ where: { name }, update: { rank, description }, create: { name, rank, description } });
  await logAudit((req as any).user?.id ?? null, 'admin.roles.upsert', req, { name, rank });
  res.json(role);
});

router.delete('/roles/:name', adminGuard, async (req, res) => {
  const name = req.params.name;
  try {
    await prisma.role.delete({ where: { name } });
    await logAudit((req as any).user?.id ?? null, 'admin.roles.delete', req, { name });
    res.status(204).end();
  } catch (err: any) {
    return res.status(404).json({ error: 'not found' });
  }
});

// Permissions list and grant/revoke to roles
router.get('/permissions', adminGuard, async (_req, res) => {
  const perms = await prisma.permission.findMany({ orderBy: { name: 'asc' } });
  res.json(perms);
});

const GrantSchema = z.object({ roleName: z.string().min(1), permission: z.string().min(1) });
router.post('/permissions/grant', adminGuard, async (req, res) => {
  const parsed = GrantSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { roleName, permission } = parsed.data;
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  const perm = await prisma.permission.findUnique({ where: { name: permission } });
  if (!role || !perm) return res.status(404).json({ error: 'role or permission not found' });
  await prisma.rolePermission.upsert({
    where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } as any },
    update: {},
    create: { roleId: role.id, permissionId: perm.id },
  });
  await logAudit((req as any).user?.id ?? null, 'admin.permissions.grant', req, { roleName, permission });
  res.json({ ok: true });
});

router.post('/permissions/revoke', adminGuard, async (req, res) => {
  const parsed = GrantSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { roleName, permission } = parsed.data;
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  const perm = await prisma.permission.findUnique({ where: { name: permission } });
  if (!role || !perm) return res.status(404).json({ error: 'role or permission not found' });
  await prisma.rolePermission.delete({ where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } as any } });
  await logAudit((req as any).user?.id ?? null, 'admin.permissions.revoke', req, { roleName, permission });
  res.json({ ok: true });
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
  const actorId = (req as any).user?.id as string;
  const actorRoles = await prisma.userRole.findMany({ where: { userId: actorId }, include: { role: true } });
  const isSystemAdmin = actorRoles.some((ur: any) => ur.role?.name === 'system_admin');
  const actorMaxRank = Math.max(...actorRoles.map((ur: any) => ur.role?.rank ?? 0), 0);
  if (!isSystemAdmin) {
    // management-level staff or higher
    const allowedManagers = ['admin', 'shelter_admin', 'staff_manager'];
    const hasManagerRole = actorRoles.some((ur: any) => allowedManagers.includes(ur.role?.name));
    if (!hasManagerRole) return res.status(403).json({ error: 'forbidden' });
    if (role.rank >= actorMaxRank) return res.status(403).json({ error: 'cannot assign same or higher rank' });
  }
  // system_admin can assign any role, including system_admin
  const ur = await prisma.userRole.upsert({
    where: { userId_roleId: { userId, roleId: role.id } as any },
    update: {},
    create: { userId, roleId: role.id },
  });
  await logAudit((req as any).user?.id ?? null, 'admin.users.assign_role', req, { userId, roleName });
  res.json(ur);
});

router.post('/users/revoke-role', adminGuard, async (req, res) => {
  const parsed = AssignRoleSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { userId, roleName } = parsed.data;
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  if (!role) return res.status(404).json({ error: 'role not found' });
  // Apply same manager/system_admin constraint for revocation
  const actorId = (req as any).user?.id as string;
  const actorRoles = await prisma.userRole.findMany({ where: { userId: actorId }, include: { role: true } });
  const isSystemAdmin = actorRoles.some((ur: any) => ur.role?.name === 'system_admin');
  const actorMaxRank = Math.max(...actorRoles.map((ur: any) => ur.role?.rank ?? 0), 0);
  if (!isSystemAdmin) {
    const allowedManagers = ['admin', 'shelter_admin', 'staff_manager'];
    const hasManagerRole = actorRoles.some((ur: any) => allowedManagers.includes(ur.role?.name));
    if (!hasManagerRole) return res.status(403).json({ error: 'forbidden' });
    if (role.rank >= actorMaxRank) return res.status(403).json({ error: 'cannot revoke same or higher rank' });
  }
  await prisma.userRole.delete({ where: { userId_roleId: { userId, roleId: role.id } as any } });
  await logAudit((req as any).user?.id ?? null, 'admin.users.revoke_role', req, { userId, roleName });
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
  const writes = [] as any[];
  for (const { key, value } of entries) {
    writes.push(prisma.setting.upsert({
      where: { category_key: { category, key } as any },
      create: { category, key, value, updatedBy: actorId || undefined },
      update: { value, updatedBy: actorId || undefined },
    }));
  }
  await prisma.$transaction(writes);
  await logAudit(actorId, 'admin.settings.upsert', req, { category, keys: entries.map(e => e.key) });
  res.json({ ok: true });
});

// ----------------------
// Audit Logs listing
// ----------------------

const auditGuard = requireRole('admin', 'system_admin');
router.get('/audit', auditGuard, async (req: any, res) => {
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
