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
  await prisma.userRole.delete({ where: { userId_roleId: { userId, roleId: role.id } as any } });
  await logAudit((req as any).user?.id ?? null, 'admin.users.revoke_role', req, { userId, roleName });
  res.json({ ok: true });
});

export default router;
