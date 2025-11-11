// Minimal local shapes to avoid relying on generated Prisma types in interfaces.
export type MenuRow = {
  id: string;
  name: string;
  title?: string | null;
  description?: string | null;
  locale?: string | null;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
};

export type MenuItemRow = {
  id: string;
  menuId: string;
  parentId?: string | null;
  title: string;
  url?: string | null;
  icon?: string | null;
  target?: string | null;
  external?: boolean;
  order?: number | null;
  meta?: any;
  isVisible?: boolean;
  isPublished?: boolean;
  locale?: string | null;
  createdAt: Date;
  updatedAt: Date;
  children?: MenuItemRow[];
};

export interface IMenuService {
  listMenus(locale?: string): Promise<(MenuRow & { items: MenuItemRow[] })[]>;
  getMenuById(id: string): Promise<(MenuRow & { items: MenuItemRow[] }) | null>;
  getMenuByName(name: string): Promise<(MenuRow & { items: MenuItemRow[] }) | null>;
  createMenu(data: { name: string; title?: string | null; description?: string | null; locale?: string | null; isActive?: boolean }): Promise<MenuRow>;
  updateMenu(id: string, data: Partial<{ name: string; title: string | null; description: string | null; locale: string | null; isActive: boolean }>): Promise<MenuRow>;
  deleteMenu(id: string): Promise<MenuRow>;

  getItemsForMenu(menuId: string): Promise<MenuItemRow[]>;
  createMenuItem(data: Partial<MenuItemRow> & { menuId: string }): Promise<MenuItemRow>;
  updateMenuItem(id: string, data: Partial<MenuItemRow>): Promise<MenuItemRow>;
  deleteMenuItem(id: string): Promise<MenuItemRow>;

  // utility
  buildTree(items: MenuItemRow[]): MenuItemRow[];
}

export default IMenuService;
