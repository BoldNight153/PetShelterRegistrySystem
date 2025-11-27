import type { AuthenticatorCatalogSeed } from '@petshelter/authenticator-catalog';
import type { SettingsMap, JsonValue } from './types';
export type { SettingsMap, JsonValue };

export type AuthenticatorFactorType = AuthenticatorCatalogSeed['factorType'];

export type AdminAuthenticatorCatalogRecord = {
  id: string;
  label: string;
  description?: string | null;
  factorType: AuthenticatorFactorType;
  issuer?: string | null;
  helper?: string | null;
  docsUrl?: string | null;
  tags?: string[] | null;
  metadata?: JsonValue | null;
  sortOrder?: number | null;
  isArchived?: boolean | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  archivedAt?: string | null;
  archivedBy?: string | null;
};

export type CreateAdminAuthenticatorInput = {
  id: string;
  label: string;
  description?: string | null;
  factorType: AuthenticatorFactorType;
  issuer?: string | null;
  helper?: string | null;
  docsUrl?: string | null;
  tags?: string[] | null;
  metadata?: JsonValue | null;
  sortOrder?: number | null;
};

export type UpdateAdminAuthenticatorInput = Partial<Omit<CreateAdminAuthenticatorInput, 'id'>>;

export interface IAdminAuthenticatorCatalogService {
  list(options?: { includeArchived?: boolean }): Promise<AdminAuthenticatorCatalogRecord[]>;
  create(input: CreateAdminAuthenticatorInput): Promise<AdminAuthenticatorCatalogRecord>;
  update(id: string, input: UpdateAdminAuthenticatorInput): Promise<AdminAuthenticatorCatalogRecord>;
  archive(id: string): Promise<void>;
  restore(id: string): Promise<void>;
}

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
  authenticators: IAdminAuthenticatorCatalogService;
}
