import express from 'express';
// zod not used in this router; keep imports minimal
import { prismaClient as prisma } from '../prisma/client';
import type { AuthUser } from '../middleware/auth';

type NavigationService = {
  list?: () => Promise<unknown[]>;
  getByName?: (name: string) => Promise<unknown>;
};
function resolveNavigationService(req: any): NavigationService | null {
  try { return req.container?.resolve('navigationService') as NavigationService; } catch { return null; }
}

const router = express.Router();

// List available menus
router.get('/', async (_req, res) => {
  const svc = resolveNavigationService(_req);
  if (svc?.list) return res.json(await svc.list());
  const menus = await prisma.menu.findMany({ select: { id: true, name: true, title: true, description: true, locale: true, isActive: true, createdAt: true, updatedAt: true } });
  res.json(menus);
});

// Helper to build nested tree from flat items array
type NavItemBase = { id: string; parentId?: string | null; order?: number | null } & Record<string, unknown>;
type NodeWithChildren = Record<string, unknown> & { children?: Array<Record<string, unknown>>; order?: number | null };
function buildTree(items: NavItemBase[]): Array<Record<string, unknown>> {
  const byId: Record<string, NavItemBase & { children: Array<Record<string, unknown>> }> = {};
  for (const it of items) byId[it.id] = { ...it, children: [] };
  const roots: Array<Record<string, unknown>> = [];
  for (const it of items) {
    if (it.parentId && byId[it.parentId]) {
      byId[it.parentId].children.push(byId[it.id]);
    } else {
      roots.push(byId[it.id]);
    }
  }
  // Ensure ordering recursively
  const sortRec = (arr: NodeWithChildren[]) => {
    arr.sort((a, b) => (a.order || 0) - (b.order || 0));
    for (const c of arr) sortRec(c.children ?? []);
  };
  sortRec(roots as NodeWithChildren[]);
  return roots;
}

type AccessMeta = {
  requiresRoles?: unknown;
  requiresPermissions?: unknown;
};

function filterTreeForUser(nodes: Array<Record<string, unknown>>, user: AuthUser | undefined): Array<Record<string, unknown>> {
  const roles = user?.roles ?? [];
  const permissions = user?.permissions ?? [];

  const result: Array<Record<string, unknown>> = [];

  for (const rawNode of nodes) {
    const node = { ...rawNode } as NodeWithChildren & {
      meta?: AccessMeta | null;
      isVisible?: boolean | null;
      isPublished?: boolean | null;
      url?: string | null;
    };

    const children = Array.isArray(node.children) ? filterTreeForUser(node.children, user) : [];
    node.children = children;

    if (node.isVisible === false || node.isPublished === false) continue;

    const meta = node.meta && typeof node.meta === 'object' ? node.meta : undefined;
    const rawRoles = meta?.requiresRoles;
    const requiresRoles = Array.isArray(rawRoles) ? rawRoles.filter((r): r is string => typeof r === 'string') : [];
    if (requiresRoles.length && !requiresRoles.some(r => roles.includes(r))) continue;

    const rawPermissions = meta?.requiresPermissions;
    const requiresPermissions = Array.isArray(rawPermissions)
      ? rawPermissions.filter((p): p is string => typeof p === 'string')
      : [];
    if (requiresPermissions.length && !requiresPermissions.every(p => permissions.includes(p))) continue;

    if (!node.url && (!node.children || node.children.length === 0)) {
      // Grouping node with no accessible children – skip
      continue;
    }

    result.push(node);
  }

  return result;
}

function applyMenuFilter(payload: unknown, user: AuthUser | undefined) {
  if (!payload || typeof payload !== 'object') return payload;
  const data = payload as Record<string, unknown>;
  const items = Array.isArray(data.items) ? filterTreeForUser(data.items as Array<Record<string, unknown>>, user) : [];
  return { ...data, items };
}

// Get menu by name (e.g. "main") and return nested items
router.get('/:name', async (req, res) => {
  const name = req.params.name;
  const svc = resolveNavigationService(req);
  const user = (req as unknown as Record<string, unknown>).user as AuthUser | undefined;
  if (svc?.getByName) {
    const m = await svc.getByName(name);
    if (!m) return res.status(404).json({ error: 'not found' });
    return res.json(applyMenuFilter(m, user));
  }

  const menu = await prisma.menu.findUnique({ where: { name } });
  if (!menu) return res.status(404).json({ error: 'not found' });
  const items = await prisma.menuItem.findMany({ where: { menuId: menu.id }, orderBy: { order: 'asc' } });
  const mapped = items.map(i => ({
    id: i.id,
    parentId: i.parentId,
    title: i.title,
    url: i.url,
    icon: i.icon,
    target: i.target,
    external: i.external,
    order: i.order,
    meta: i.meta,
    isVisible: i.isVisible,
    isPublished: i.isPublished,
    locale: i.locale,
  } as NavItemBase));
  const tree = buildTree(mapped);
  const filtered = filterTreeForUser(tree, user);
  res.json({ ...menu, items: filtered });
});

export default router;
