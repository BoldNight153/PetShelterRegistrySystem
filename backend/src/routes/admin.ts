import express from 'express';
import { Prisma } from '@prisma/client';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { requireRole } from '../middleware/auth';
import { resetPasswordEmailTemplate, sendMail } from '../lib/email';
import { AuditService } from '../services/auditService';
import { normalizeAuditSettings } from '../types/auditSettings';
import { DEFAULT_AUTH_SETTINGS, normalizeAuthSettingEntry, normalizeAuthSettings } from '../types/authSettings';
import type { IAuthenticatorCatalogService, AuthenticatorCatalogInput, AuthenticatorCatalogUpdate } from '../services/interfaces/authenticatorCatalogService.interface';

const router = express.Router();
// use centralized prisma client
const ERR = { notFound: 'user not found' } as const;
const ERR_ROLE_OR_PERMISSION_NOT_FOUND = 'role or permission not found' as const;
const ERROR_AUTHENTICATOR_NOT_FOUND = 'authenticator not found' as const;

async function resolveAuthenticatorIdBuckets() {
  const rows = await prisma.authenticatorCatalog.findMany({
    orderBy: { sortOrder: 'asc' },
    select: { id: true, isArchived: true },
  });
  if (!rows.length) {
    const defaults = [...DEFAULT_AUTH_SETTINGS.authenticators];
    return { allowedIds: defaults, fallbackIds: defaults };
  }
  const allowedIds = rows.map(entry => entry.id);
  const activeIds = rows.filter(entry => !entry.isArchived).map(entry => entry.id);
  const fallbackIds = activeIds.length ? activeIds : allowedIds;
  return { allowedIds, fallbackIds };
}

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
    } catch {
      return res.status(404).json({ error: ERR_ROLE_OR_PERMISSION_NOT_FOUND });
    }
  }
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  const perm = await prisma.permission.findUnique({ where: { name: permission } });
  if (!role || !perm) return res.status(404).json({ error: ERR_ROLE_OR_PERMISSION_NOT_FOUND });
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
    } catch {
      return res.status(404).json({ error: ERR_ROLE_OR_PERMISSION_NOT_FOUND });
    }
  }
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  const perm = await prisma.permission.findUnique({ where: { name: permission } });
  if (!role || !perm) return res.status(404).json({ error: ERR_ROLE_OR_PERMISSION_NOT_FOUND });
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
  const q = typeof rawQ === 'string' ? rawQ.trim() : '';
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
  try { (req as unknown as Record<string, any>).log?.error('user listing failed', { err }); } catch {}
    res.status(500).json({ error: 'Failed to list users' });
  }
});

// Manual lock a user (staff_manager and higher)
const staffGuard = requireRole('staff_manager', 'shelter_admin', 'admin', 'system_admin');
router.post('/users/lock', staffGuard, async (req: any, res) => {
  const { userId, reason, expiresAt, notes } = req.body || {};
  if (!userId || !reason) return res.status(400).json({ error: 'userId and reason are required' });
  const userIdStr = String(userId);
  const user = await prisma.user.findUnique({ where: { id: userIdStr } });
  if (!user) return res.status(404).json({ error: ERR.notFound });
  const data: any = { userId: userIdStr, reason: String(reason), manual: true, lockedAt: new Date(), lockedBy: req.user?.id || null };
  if (expiresAt) data.expiresAt = new Date(String(expiresAt));
  if (notes) data.notes = String(notes);
  const maybeUserService = req.container?.resolve?.('userService') as import('../services/interfaces/userService.interface').IUserService | undefined;
  if (maybeUserService && typeof maybeUserService.lockUser === 'function') {
  const lock = await maybeUserService.lockUser(userIdStr, { reason: String(reason), expiresAt: data.expiresAt ?? null, notes: data.notes ?? null, actorId: req.user?.id || null });
  await logAudit(String(req.user?.id ?? '' ) || null, 'admin.users.lock', req, { userId: userIdStr, reason, expiresAt: data.expiresAt ?? null });
    return res.json({ ok: true, lock });
  }
  const lock = await prisma.userLock.create({ data });
  await logAudit(String(req.user?.id ?? '' ) || null, 'admin.users.lock', req, { userId: userIdStr, reason, expiresAt: data.expiresAt ?? null });
  res.json({ ok: true, lock });
});

// Manual unlock a user — sends password reset email and revokes sessions
router.post('/users/unlock', staffGuard, async (req: any, res) => {
  const { userId, unlockReason } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId is required' });
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return res.status(404).json({ error: 'user not found' });
  const maybeUserService = (req as unknown as Record<string, any>).container?.resolve?.('userService');
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

// ----------------------
// Admin: Menus & MenuItems CRUD
// ----------------------
// Admins and system_admins can manage menus and their items
const menusGuard = adminGuard;

const MenuCreateSchema = z.object({
  name: z.string().min(1),
  title: z.string().optional(),
  description: z.string().optional(),
  locale: z.string().optional(),
  isActive: z.boolean().optional(),
});

const MenuUpdateSchema = z.object({
  title: z.string().optional(),
  description: z.string().optional(),
  locale: z.string().optional(),
  isActive: z.boolean().optional(),
});

const MenuItemCreateSchema = z.object({
  title: z.string().min(1),
  url: z.string().optional(),
  icon: z.string().optional(),
  target: z.string().optional(),
  external: z.boolean().optional(),
  order: z.number().int().optional(),
  meta: z.unknown().optional(),
  parentId: z.string().optional(),
  isVisible: z.boolean().optional(),
  isPublished: z.boolean().optional(),
  locale: z.string().optional(),
});

const MenuItemUpdateSchema = z.object({
  title: z.string().optional(),
  url: z.string().optional(),
  icon: z.string().optional(),
  target: z.string().optional(),
  external: z.boolean().optional(),
  order: z.number().int().optional(),
  meta: z.unknown().optional(),
  parentId: z.string().nullable().optional(),
  isVisible: z.boolean().optional(),
  isPublished: z.boolean().optional(),
  locale: z.string().optional(),
});

function buildTree(items: Array<Record<string, unknown>>) : Array<Record<string, unknown>> {
  type Node = Record<string, unknown> & { id: string; parentId?: string | null; order?: number | null; children?: Node[] };
  const byId: Record<string, Node> = {};
  const roots: Node[] = [];
  for (const it of items) {
    const node = { ...it } as Node;
    node.children = [];
    byId[node.id] = node;
  }
  for (const it of items) {
  const id = String(it['id']);
  const parentId = it['parentId'] as string | undefined | null;
    const parent = parentId ? byId[parentId] : undefined;
    if (parent) parent.children!.push(byId[id]);
    else roots.push(byId[id]);
  }
  // sort children by order
  function sortRec(node: Node) {
    if (!node.children) return;
    node.children.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
    for (const c of node.children) sortRec(c);
  }
  for (const r of roots) sortRec(r);
  return roots.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
}
// List all menus with nested items
router.get('/menus', menusGuard, async (req, res) => {
  const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
  if (maybeMenuService && typeof maybeMenuService.listMenus === 'function') {
    const menus = await maybeMenuService.listMenus();
    return res.json(menus);
  }
  const menus = await prisma.menu.findMany({ include: { items: { orderBy: { order: 'asc' } } }, orderBy: { name: 'asc' } });
  const shaped = menus.map(m => ({ id: m.id, name: m.name, title: m.title, description: m.description, locale: m.locale, isActive: m.isActive, createdAt: m.createdAt, updatedAt: m.updatedAt, items: buildTree(((m.items || []) as unknown[]).map((it) => ({ ...(it as Record<string, unknown>) }))) }));
  res.json(shaped);
});

// Get single menu by name
router.get('/menus/:name', menusGuard, async (req, res) => {
  const name = req.params.name;
  const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
  if (maybeMenuService && typeof maybeMenuService.getMenuByName === 'function') {
    const menu = await maybeMenuService.getMenuByName(name);
    if (!menu) return res.status(404).json({ error: 'not found' });
    return res.json(menu);
  }
  const menu = await prisma.menu.findUnique({ where: { name }, include: { items: { orderBy: { order: 'asc' } } } });
  if (!menu) return res.status(404).json({ error: 'not found' });
  const shaped = { id: menu.id, name: menu.name, title: menu.title, description: menu.description, locale: menu.locale, isActive: menu.isActive, createdAt: menu.createdAt, updatedAt: menu.updatedAt, items: buildTree(((menu.items || []) as unknown[]).map((it) => ({ ...(it as Record<string, unknown>) }))) };
  res.json(shaped);
});

// Create a menu
router.post('/menus', menusGuard, async (req: any, res) => {
  const parsed = MenuCreateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { name, title, description, locale, isActive } = parsed.data;
  try {
    const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
    let menu;
    if (maybeMenuService && typeof maybeMenuService.createMenu === 'function') {
      menu = await maybeMenuService.createMenu({ name, title: title ?? undefined, description: description ?? undefined, locale: locale ?? undefined, isActive: isActive ?? true });
    } else {
      menu = await prisma.menu.create({ data: { name, title: title ?? undefined, description: description ?? undefined, locale: locale ?? undefined, isActive: isActive ?? true } });
    }
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.menus.create', req, { id: menu.id, name });
    res.json(menu);
  } catch {
    return res.status(400).json({ error: 'failed to create menu' });
  }
});

// Update menu
router.put('/menus/:id', menusGuard, async (req: any, res) => {
  const parsed = MenuUpdateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { id } = req.params as { id: string };
  try {
    const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
    let menu;
      if (maybeMenuService && typeof maybeMenuService.updateMenu === 'function') {
        // service expects a simple Partial of menu fields
        menu = await maybeMenuService.updateMenu(id, parsed.data as unknown as Partial<{ name: string; title: string | null; description: string | null; locale: string | null; isActive: boolean }>);
      } else {
        menu = await prisma.menu.update({ where: { id }, data: parsed.data as unknown as Prisma.MenuUpdateInput });
      }
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.menus.update', req, { id });
    res.json(menu);
  } catch {
    return res.status(404).json({ error: 'not found' });
  }
});

// Delete menu
router.delete('/menus/:id', menusGuard, async (req: any, res) => {
  const { id } = req.params as { id: string };
  try {
    const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
    if (maybeMenuService && typeof maybeMenuService.deleteMenu === 'function') {
      await maybeMenuService.deleteMenu(id);
    } else {
      await prisma.menu.delete({ where: { id } });
    }
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.menus.delete', req, { id });
    res.status(204).end();
  } catch {
    return res.status(404).json({ error: 'not found' });
  }
});

// Menu items routes
router.get('/menus/:menuId/items', menusGuard, async (req, res) => {
  const { menuId } = req.params as { menuId: string };
  const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
  if (maybeMenuService && typeof maybeMenuService.getItemsForMenu === 'function') {
    const items = await maybeMenuService.getItemsForMenu(menuId);
    return res.json(items);
  }
  const items = await prisma.menuItem.findMany({ where: { menuId }, orderBy: { order: 'asc' } });
  res.json(buildTree(((items || []) as unknown[]).map((it) => ({ ...(it as Record<string, unknown>) }))));
});

router.post('/menus/:menuId/items', menusGuard, async (req: any, res) => {
  const parsed = MenuItemCreateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { menuId } = req.params as { menuId: string };
  const data: any = { menuId, title: parsed.data.title, url: parsed.data.url ?? undefined, icon: parsed.data.icon ?? undefined, target: parsed.data.target ?? undefined, external: parsed.data.external ?? false, order: parsed.data.order ?? 0, meta: parsed.data.meta ?? undefined, parentId: parsed.data.parentId ?? undefined, isVisible: parsed.data.isVisible ?? true, isPublished: parsed.data.isPublished ?? true, locale: parsed.data.locale ?? undefined };
  try {
    const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
    let item;
    if (maybeMenuService && typeof maybeMenuService.createMenuItem === 'function') {
      item = await maybeMenuService.createMenuItem(data as unknown as Partial<import('../services/interfaces/menuService.interface').MenuItemRow> & { menuId: string });
    } else {
      item = await prisma.menuItem.create({ data: data as unknown as Prisma.MenuItemCreateInput });
    }
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.menuItems.create', req, { id: item.id, menuId });
    res.json(item);
  } catch {
    return res.status(400).json({ error: 'failed to create item' });
  }
});

router.put('/menus/items/:id', menusGuard, async (req: any, res) => {
  const parsed = MenuItemUpdateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { id } = req.params as { id: string };
  try {
    const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
    let item;
    if (maybeMenuService && typeof maybeMenuService.updateMenuItem === 'function') {
      item = await maybeMenuService.updateMenuItem(id, parsed.data as unknown as Partial<import('../services/interfaces/menuService.interface').MenuItemRow>);
    } else {
      item = await prisma.menuItem.update({ where: { id }, data: parsed.data as unknown as Prisma.MenuItemUpdateInput });
    }
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.menuItems.update', req, { id });
    res.json(item);
  } catch {
    return res.status(404).json({ error: 'not found' });
  }
});

router.delete('/menus/items/:id', menusGuard, async (req: any, res) => {
  const { id } = req.params as { id: string };
  try {
    const maybeMenuService = req.container?.resolve?.('menuService') as import('../services/interfaces/menuService.interface').IMenuService | undefined;
    if (maybeMenuService && typeof maybeMenuService.deleteMenuItem === 'function') {
      await maybeMenuService.deleteMenuItem(id);
    } else {
      await prisma.menuItem.delete({ where: { id } });
    }
    await logAudit(String(req.user?.id ?? '' ) || null, 'admin.menuItems.delete', req, { id });
    res.status(204).end();
  } catch {
    return res.status(404).json({ error: 'not found' });
  }
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
    const settings = await maybeSettings.listSettings(category, { preserveUnknownAuth: true });
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
  if (!category || category === 'audit') {
    result.audit = normalizeAuditSettings(result.audit as Record<string, unknown> | null | undefined);
  }
  if (!category || category === 'auth') {
    const { allowedIds, fallbackIds } = await resolveAuthenticatorIdBuckets();
    result.auth = normalizeAuthSettings(result.auth as Record<string, unknown> | null | undefined, {
      allowedAuthenticatorIds: allowedIds,
      fallbackAuthenticators: fallbackIds,
      preserveUnknown: true,
    });
  }
  res.json({ settings: result });
});

// Upsert settings for a category; body: { category: string, entries: { key: string, value: any }[] }
const UpsertSettingsSchema = z.object({
  category: z.string().min(1),
  entries: z.array(z.object({ key: z.string().min(1), value: z.unknown() })).min(1),
});

router.put('/settings', settingsGuard, async (req: any, res) => {
  const parsed = UpsertSettingsSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { category, entries } = parsed.data;
  const actorId = req.user?.id || null;
  const maybeSettings = req.container?.resolve?.('settingsService');
  if (maybeSettings && typeof maybeSettings.upsertSettings === 'function') {
    await maybeSettings.upsertSettings(category, entries, actorId);
    await logAudit((typeof actorId === 'string' ? actorId : null), 'admin.settings.upsert', req, { category, keys: entries.map((e: { key: string }) => e.key) });
    return res.json({ ok: true });
  }
  const writes: Array<Prisma.PrismaPromise<any>> = [];
  let allowedAuthenticatorIds: string[] | undefined;
  let fallbackAuthenticatorIds: string[] | undefined;
  if (category === 'auth') {
    const buckets = await resolveAuthenticatorIdBuckets();
    allowedAuthenticatorIds = buckets.allowedIds;
    fallbackAuthenticatorIds = buckets.fallbackIds;
  }
  for (const { key, value } of entries) {
    const sanitized = category === 'auth'
      ? normalizeAuthSettingEntry(key, value, {
          allowedAuthenticatorIds,
          fallbackAuthenticators: fallbackAuthenticatorIds ?? allowedAuthenticatorIds,
        })
      : value;
    const normalizedValue = sanitized as Prisma.InputJsonValue;
    writes.push(prisma.setting.upsert({
      where: { category_key: { category, key } },
      create: { category, key, value: normalizedValue, updatedBy: actorId || undefined },
      update: { value: normalizedValue, updatedBy: actorId || undefined },
    }));
  }
  await prisma.$transaction(writes);
  await logAudit((typeof actorId === 'string' ? actorId : null), 'admin.settings.upsert', req, { category, keys: entries.map((e: { key: string }) => e.key) });
  res.json({ ok: true });
});

// ----------------------
// Authenticator catalog management
// ----------------------

const authenticatorGuard = requireRole('system_admin');
const FactorTypeSchema = z.preprocess(
  value => (typeof value === 'string' ? value.trim().toUpperCase() : value),
  z.enum(['TOTP', 'SMS', 'PUSH', 'HARDWARE_KEY', 'BACKUP_CODES']),
); // Coerce lowercase inputs to the canonical enum
const optionalUrlSchema = z.preprocess(
  value => (typeof value === 'string' && value.trim().length === 0 ? null : value),
  z.string().url().optional().nullable(),
);
const normalizeOptionalString = (value: string | null | undefined): string | null | undefined => {
  if (typeof value === 'undefined') return undefined;
  if (value === null) return null;
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
};
const JsonValueSchema: z.ZodType<Prisma.JsonValue> = z.lazy(() => z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.null(),
  z.array(JsonValueSchema),
  z.record(z.string(), JsonValueSchema),
]));
const toNullableJsonInput = (
  value: Prisma.JsonValue | string[] | null | undefined,
): Prisma.InputJsonValue | Prisma.NullableJsonNullValueInput | undefined => {
  if (typeof value === 'undefined') return undefined;
  if (value === null) return Prisma.JsonNull;
  return value as Prisma.InputJsonValue;
};

const AuthenticatorBaseSchema = z.object({
  label: z.string().min(1).max(160),
  description: z.string().max(500).optional().nullable(),
  factorType: FactorTypeSchema,
  issuer: z.string().max(160).optional().nullable(),
  helper: z.string().max(500).optional().nullable(),
  docsUrl: optionalUrlSchema,
  tags: z.array(z.string().min(1).max(40)).max(10).optional().nullable(),
  metadata: z.record(z.string(), z.unknown()).optional().nullable(),
  sortOrder: z.number().int().optional().nullable(),
});

const AuthenticatorCreateSchema = AuthenticatorBaseSchema.extend({
  id: z.string().min(2).max(120).regex(/^[a-z0-9_\-]+$/i),
});

const AuthenticatorUpdateSchema = AuthenticatorBaseSchema.partial();

router.get('/authenticators', authenticatorGuard, async (req: any, res) => {
  const includeArchived = String(req.query.includeArchived || '').toLowerCase() === 'true';
  const maybeCatalog = req.container?.resolve?.('authenticatorCatalogService') as IAuthenticatorCatalogService | undefined;
  const authenticators = maybeCatalog && typeof maybeCatalog.list === 'function'
    ? await maybeCatalog.list({ includeArchived })
    : await prisma.authenticatorCatalog.findMany({
        where: includeArchived ? {} : { isArchived: false },
        orderBy: { sortOrder: 'asc' },
      });
  res.json({ authenticators });
});

router.post('/authenticators', authenticatorGuard, async (req: any, res) => {
  const parsed = AuthenticatorCreateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const actorId = req.user?.id || null;
  const maybeCatalog = req.container?.resolve?.('authenticatorCatalogService') as IAuthenticatorCatalogService | undefined;
  const payload = parsed.data;
  const normalizedSortOrder = typeof payload.sortOrder === 'number' ? payload.sortOrder : 0;
  const normalizedPayload: AuthenticatorCatalogInput = {
    ...payload,
    description: normalizeOptionalString(payload.description),
    issuer: normalizeOptionalString(payload.issuer),
    helper: normalizeOptionalString(payload.helper),
    docsUrl: normalizeOptionalString(payload.docsUrl),
    tags: payload.tags ?? undefined,
    metadata: typeof payload.metadata === 'undefined' ? null : (payload.metadata as Prisma.JsonValue | null),
    sortOrder: normalizedSortOrder,
  };
  const { sortOrder: _ignoredSortOrder, ...restPayload } = normalizedPayload;
  try {
    const created = maybeCatalog && typeof maybeCatalog.create === 'function'
      ? await maybeCatalog.create(normalizedPayload, actorId)
      : await prisma.authenticatorCatalog.create({
          data: {
            ...restPayload,
            description: normalizeOptionalString(payload.description) ?? null,
            issuer: normalizeOptionalString(payload.issuer) ?? null,
            helper: normalizeOptionalString(payload.helper) ?? null,
            docsUrl: normalizeOptionalString(payload.docsUrl) ?? null,
            tags: toNullableJsonInput(payload.tags ?? null),
            metadata: toNullableJsonInput(typeof payload.metadata === 'undefined' ? null : (payload.metadata as Prisma.JsonValue | null)),
            sortOrder: normalizedSortOrder,
            createdBy: actorId ?? null,
            updatedBy: actorId ?? null,
            isSystem: false,
          },
        });
    await logAudit(actorId ?? null, 'admin.authenticators.create', req, { id: payload.id });
    return res.status(201).json({ authenticator: created });
  } catch (err) {
    return res.status(400).json({ error: 'failed to create authenticator', details: String((err as Error)?.message ?? err) });
  }
});

router.put('/authenticators/:id', authenticatorGuard, async (req: any, res) => {
  const parsed = AuthenticatorUpdateSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const actorId = req.user?.id || null;
  const { id } = req.params as { id: string };
  const normalizedUpdateInput: AuthenticatorCatalogUpdate = {
    ...parsed.data,
    description: normalizeOptionalString(parsed.data.description),
    issuer: normalizeOptionalString(parsed.data.issuer),
    helper: normalizeOptionalString(parsed.data.helper),
    docsUrl: normalizeOptionalString(parsed.data.docsUrl),
    tags: Array.isArray(parsed.data.tags) ? parsed.data.tags : undefined,
    metadata: typeof parsed.data.metadata === 'undefined' ? undefined : (parsed.data.metadata as Prisma.JsonValue | null),
    sortOrder: typeof parsed.data.sortOrder === 'number' ? parsed.data.sortOrder : undefined,
  };
  const maybeCatalog = req.container?.resolve?.('authenticatorCatalogService') as IAuthenticatorCatalogService | undefined;
  try {
    const updated = maybeCatalog && typeof maybeCatalog.update === 'function'
      ? await maybeCatalog.update(id, normalizedUpdateInput, actorId)
      : await prisma.authenticatorCatalog.update({
          where: { id },
          data: {
            ...parsed.data,
            description: typeof normalizedUpdateInput.description === 'undefined' ? undefined : normalizedUpdateInput.description,
            issuer: typeof normalizedUpdateInput.issuer === 'undefined' ? undefined : normalizedUpdateInput.issuer,
            helper: typeof normalizedUpdateInput.helper === 'undefined' ? undefined : normalizedUpdateInput.helper,
            docsUrl: typeof normalizedUpdateInput.docsUrl === 'undefined' ? undefined : normalizedUpdateInput.docsUrl,
            tags: toNullableJsonInput(parsed.data.tags),
            metadata: typeof parsed.data.metadata === 'undefined'
              ? undefined
              : toNullableJsonInput((parsed.data.metadata ?? null) as Prisma.JsonValue | null),
            sortOrder: typeof parsed.data.sortOrder === 'number' ? parsed.data.sortOrder : undefined,
            updatedBy: actorId ?? undefined,
          },
        });
    await logAudit(actorId ?? null, 'admin.authenticators.update', req, { id });
    return res.json({ authenticator: updated });
  } catch {
    return res.status(404).json({ error: ERROR_AUTHENTICATOR_NOT_FOUND });
  }
});

router.post('/authenticators/:id/archive', authenticatorGuard, async (req: any, res) => {
  const { id } = req.params as { id: string };
  const actorId = req.user?.id || null;
  const maybeCatalog = req.container?.resolve?.('authenticatorCatalogService') as IAuthenticatorCatalogService | undefined;
  try {
    if (maybeCatalog && typeof maybeCatalog.archive === 'function') {
      await maybeCatalog.archive(id, actorId);
    } else {
      const authenticator = await prisma.authenticatorCatalog.findUnique({ where: { id } });
      if (authenticator?.isSystem) {
        return res.status(400).json({ error: 'System authenticators cannot be archived' });
      }
      await prisma.authenticatorCatalog.update({
        where: { id },
        data: { isArchived: true, archivedAt: new Date(), archivedBy: actorId ?? null },
      });
    }
    await logAudit(actorId ?? null, 'admin.authenticators.archive', req, { id });
    return res.json({ ok: true });
  } catch (err) {
    const message = (err as Error)?.message || ERROR_AUTHENTICATOR_NOT_FOUND;
    return res.status(400).json({ error: message });
  }
});

router.post('/authenticators/:id/restore', authenticatorGuard, async (req: any, res) => {
  const { id } = req.params as { id: string };
  const actorId = req.user?.id || null;
  const maybeCatalog = req.container?.resolve?.('authenticatorCatalogService') as IAuthenticatorCatalogService | undefined;
  try {
    if (maybeCatalog && typeof maybeCatalog.restore === 'function') {
      await maybeCatalog.restore(id, actorId);
    } else {
      await prisma.authenticatorCatalog.update({
        where: { id },
        data: { isArchived: false, archivedAt: null, archivedBy: null, updatedBy: actorId ?? undefined },
      });
    }
    await logAudit(actorId ?? null, 'admin.authenticators.restore', req, { id });
    return res.json({ ok: true });
  } catch {
    return res.status(404).json({ error: ERROR_AUTHENTICATOR_NOT_FOUND });
  }
});

// ----------------------
// Audit Logs listing
// ----------------------

const auditGuard = requireRole('admin', 'system_admin');
const fallbackAuditService = new AuditService({ prisma });
router.get('/audit', auditGuard, async (req: any, res) => {
  const params = normalizeAuditQueryParams(req.query || {});
  const maybeAudit = req.container?.resolve?.('auditService') as import('../services/interfaces/auditService.interface').IAuditService | undefined;
  if (maybeAudit && typeof maybeAudit.listAudit === 'function') {
    const result = await maybeAudit.listAudit(params);
    return res.json(result);
  }
  const result = await fallbackAuditService.listAudit(params);
  res.json(result);
});

type QueryRecord = Record<string, unknown> | undefined;

function normalizeAuditQueryParams(query: QueryRecord) {
  const source = query ?? {};
  const page = Math.max(1, parseQueryNumber(source.page, 1));
  const pageSize = Math.min(200, Math.max(1, parseQueryNumber(source.pageSize, 25)));
  return {
    q: parseQueryString(source.q),
    action: parseQueryString(source.action),
    userId: parseQueryString(source.userId),
    from: parseQueryDate(source.from),
    to: parseQueryDate(source.to),
    page,
    pageSize,
  };
}

function parseQueryString(value: unknown): string {
  if (Array.isArray(value)) return parseQueryString(value[0]);
  if (typeof value === 'string') return value.trim();
  if (value === undefined || value === null) return '';
  return String(value).trim();
}

function parseQueryNumber(value: unknown, fallback: number): number {
  if (Array.isArray(value)) return parseQueryNumber(value[0], fallback);
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function parseQueryDate(value: unknown): Date | null {
  if (Array.isArray(value)) return parseQueryDate(value[0]);
  if (value === undefined || value === null || value === '') return null;
  const date = new Date(String(value));
  return Number.isNaN(date.getTime()) ? null : date;
}
