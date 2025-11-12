import type { SettingsMap, JsonValue } from './types';
export type { SettingsMap, JsonValue };

export interface ISettingsService {
  loadSettings(category?: string): Promise<SettingsMap>;
  saveSettings(category: string, entries: { key: string; value: JsonValue }[]): Promise<unknown>;
}

export type AdminMenuRecord = {
  id: string;
  name: string;
  title?: string | null;
  description?: string | null;
  locale?: string | null;
  isActive?: boolean | null;
  createdAt?: string | null;
  updatedAt?: string | null;
};

export type AdminMenuItem = {
  id: string;
  menuId: string;
  parentId?: string | null;
  title: string;
  url?: string | null;
  icon?: string | null;
  target?: string | null;
  external?: boolean | null;
  order?: number | null;
  meta?: JsonValue;
  isVisible?: boolean | null;
  isPublished?: boolean | null;
  locale?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  children?: AdminMenuItem[];
};

export type AdminMenu = AdminMenuRecord & { items: AdminMenuItem[] };

export type CreateAdminMenuInput = {
  name: string;
  title?: string | null;
  description?: string | null;
  locale?: string | null;
  isActive?: boolean | null;
};

export type UpdateAdminMenuInput = Partial<{
  title: string | null;
  description: string | null;
  locale: string | null;
  isActive: boolean | null;
}>;

export type CreateAdminMenuItemInput = {
  title: string;
  url?: string | null;
  icon?: string | null;
  target?: string | null;
  external?: boolean | null;
  order?: number | null;
  meta?: JsonValue;
  parentId?: string | null;
  isVisible?: boolean | null;
  isPublished?: boolean | null;
  locale?: string | null;
};

export type UpdateAdminMenuItemInput = Partial<CreateAdminMenuItemInput>;

export interface IAdminNavigationService {
  listMenus(): Promise<AdminMenu[]>;
  getMenu(name: string): Promise<AdminMenu | null>;
  createMenu(input: CreateAdminMenuInput): Promise<AdminMenuRecord>;
  updateMenu(id: string, input: UpdateAdminMenuInput): Promise<AdminMenuRecord>;
  deleteMenu(id: string): Promise<void>;
  listMenuItems(menuId: string): Promise<AdminMenuItem[]>;
  createMenuItem(menuId: string, input: CreateAdminMenuItemInput): Promise<AdminMenuItem>;
  updateMenuItem(id: string, input: UpdateAdminMenuItemInput): Promise<AdminMenuItem>;
  deleteMenuItem(id: string): Promise<void>;
}

export interface IAdminService {
  settings: ISettingsService;
  navigation: IAdminNavigationService;
}
