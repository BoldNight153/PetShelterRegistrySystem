import type { PrismaClient, Menu as PrismaMenu, MenuItem as PrismaMenuItem, Prisma } from '@prisma/client';
import type IMenuService from './interfaces/menuService.interface';
import { prismaClient as sharedPrisma } from '../prisma/client';

export type MenuItemNode = PrismaMenuItem & { children?: MenuItemNode[] };

export class MenuService implements IMenuService {
  private prisma: PrismaClient;

  constructor(opts: { prisma: PrismaClient }) {
    this.prisma = opts.prisma;

    // Defensive: tests sometimes pass a mocked Prisma with limited shape.
    const mayHaveModel = (this.prisma as any)?.menu;
    if (!mayHaveModel || typeof mayHaveModel.findMany !== 'function') {
      this.prisma = sharedPrisma as unknown as PrismaClient;
    }
  }

  // Public helper so unit tests can validate tree building logic.
  // Accept a loose array to allow tests and legacy callers to pass untyped items
  static buildTree(items: Array<any>): MenuItemNode[] {
    const map: Record<string, MenuItemNode> = {};
    const roots: MenuItemNode[] = [];

    items.forEach((itRaw) => {
      const it = itRaw as PrismaMenuItem;
      map[it.id] = { ...it, children: [] };
    });

    items.forEach((itRaw) => {
      const it = itRaw as PrismaMenuItem;
      if (it.parentId) {
        const parent = map[it.parentId];
        if (parent) parent.children!.push(map[it.id]);
        else roots.push(map[it.id]);
      } else {
        roots.push(map[it.id]);
      }
    });

    // Sort children by order field (ascending) recursively
    const sortRec = (nodes: MenuItemNode[]) => {
      nodes.sort((a, b) => (a.order ?? 0) - (b.order ?? 0));
      nodes.forEach((n) => { if (n.children && n.children.length) sortRec(n.children); });
    };
    sortRec(roots);
    return roots;
  }

  // instance facade for the interface - delegates to the static helper
  // Accept loose arrays for compatibility with older test fixtures
  buildTree(items: Array<any>): MenuItemNode[] {
    return MenuService.buildTree(items);
  }

  async listMenus(locale?: string) {
    const menus = await this.prisma.menu.findMany({ where: locale ? { locale } : undefined });
    if (!menus || menus.length === 0) return [];

    // Fetch items for all menus in a single query
    const menuIds = menus.map((m) => m.id);
  const items = await this.prisma.menuItem.findMany({ where: { menuId: { in: menuIds } }, orderBy: { order: 'asc' } as const });

    // Group items by menuId and build trees
    const byMenu: Record<string, MenuItemNode[]> = {};
    menuIds.forEach((id) => { byMenu[id] = []; });
    items.forEach((it) => { if (!byMenu[it.menuId]) byMenu[it.menuId] = []; byMenu[it.menuId].push(it); });

  return menus.map((m) => ({ ...m, items: MenuService.buildTree(byMenu[m.id] || []) } as PrismaMenu & { items: MenuItemNode[] }));
  }

  async getMenuById(id: string) {
    const menu = await this.prisma.menu.findUnique({ where: { id } });
    if (!menu) return null;
  const items = await this.prisma.menuItem.findMany({ where: { menuId: id }, orderBy: { order: 'asc' } as const });
    return { ...menu, items: MenuService.buildTree(items) } as PrismaMenu & { items: MenuItemNode[] };
  }

  async getMenuByName(name: string) {
    const menu = await this.prisma.menu.findUnique({ where: { name } });
    if (!menu) return null;
  const items = await this.prisma.menuItem.findMany({ where: { menuId: menu.id }, orderBy: { order: 'asc' } as const });
    return { ...menu, items: MenuService.buildTree(items) } as PrismaMenu & { items: MenuItemNode[] };
  }

  async createMenu(data: { name: string; title?: string | null; description?: string | null; locale?: string | null; isActive?: boolean }) {
    return this.prisma.menu.create({ data });
  }

  async updateMenu(id: string, data: Partial<{ name: string; title: string | null; description: string | null; locale: string | null; isActive: boolean }>) {
    return this.prisma.menu.update({ where: { id }, data: data as unknown as Prisma.MenuUpdateInput });
  }

  async deleteMenu(id: string) {
    return this.prisma.menu.delete({ where: { id } });
  }

  async getItemsForMenu(menuId: string) {
    const items = await this.prisma.menuItem.findMany({ where: { menuId }, orderBy: { order: 'asc' } as const });
    return MenuService.buildTree(items);
  }

  async createMenuItem(data: Partial<PrismaMenuItem> & { menuId: string }) {
    return this.prisma.menuItem.create({ data: data as unknown as Prisma.MenuItemCreateInput });
  }

  async updateMenuItem(id: string, data: Partial<PrismaMenuItem>) {
    return this.prisma.menuItem.update({ where: { id }, data: data as unknown as Prisma.MenuItemUpdateInput });
  }

  async deleteMenuItem(id: string) {
    return this.prisma.menuItem.delete({ where: { id } });
  }
}

export default MenuService;
