// Runtime adapter: this file is the runtime boundary and may import runtime-only helpers
// from `frontend/src/lib/api`. UI code should not import types from that module —
// instead use the service interfaces under `services/interfaces`.
import * as api from '../../lib/api';
import type {
  ISettingsService,
  IAdminService,
  IAdminNavigationService,
  IAdminAuthenticatorCatalogService,
  AdminMenu,
  AdminMenuItem,
  AdminMenuRecord,
  AdminAuthenticatorCatalogRecord,
  CreateAdminMenuInput,
  UpdateAdminMenuInput,
  CreateAdminMenuItemInput,
  UpdateAdminMenuItemInput,
  CreateAdminAuthenticatorInput,
  UpdateAdminAuthenticatorInput,
} from '../interfaces/admin.interface';
import type { JsonValue } from '@/services/interfaces/types';

class SettingsAdapter implements ISettingsService {
  loadSettings(category?: string) {
    return api.loadSettings(category);
  }
  saveSettings(category: string, entries: { key: string; value: JsonValue }[]) {
    return api.saveSettings(category, entries);
  }
}

class AdminNavigationAdapter implements IAdminNavigationService {
  async listMenus(): Promise<AdminMenu[]> {
    const menus = await api.fetchAdminMenus();
    return menus.map((menu) => ({ ...menu })) as AdminMenu[];
  }

  async getMenu(name: string): Promise<AdminMenu | null> {
    const menu = await api.fetchAdminMenuByName(name);
    return menu ? ({ ...menu } as AdminMenu) : null;
  }

  createMenu(input: CreateAdminMenuInput): Promise<AdminMenuRecord> {
    return api.createAdminMenu(input);
  }

  updateMenu(id: string, input: UpdateAdminMenuInput): Promise<AdminMenuRecord> {
    return api.updateAdminMenu(id, input);
  }

  deleteMenu(id: string): Promise<void> {
    return api.deleteAdminMenu(id);
  }

  async listMenuItems(menuId: string): Promise<AdminMenuItem[]> {
    const items = await api.fetchAdminMenuItems(menuId);
    return items.map((item) => ({ ...item })) as AdminMenuItem[];
  }

  async createMenuItem(menuId: string, input: CreateAdminMenuItemInput): Promise<AdminMenuItem> {
    const created = await api.createAdminMenuItem(menuId, input);
    return { ...created, children: undefined } as AdminMenuItem;
  }

  async updateMenuItem(id: string, input: UpdateAdminMenuItemInput): Promise<AdminMenuItem> {
    const updated = await api.updateAdminMenuItem(id, input);
    return { ...updated, children: undefined } as AdminMenuItem;
  }

  deleteMenuItem(id: string): Promise<void> {
    return api.deleteAdminMenuItem(id);
  }
}

class AdminAuthenticatorCatalogAdapter implements IAdminAuthenticatorCatalogService {
  list(options?: { includeArchived?: boolean }): Promise<AdminAuthenticatorCatalogRecord[]> {
    return api.fetchAdminAuthenticators(options?.includeArchived);
  }

  create(input: CreateAdminAuthenticatorInput): Promise<AdminAuthenticatorCatalogRecord> {
    return api.createAdminAuthenticator(input);
  }

  update(id: string, input: UpdateAdminAuthenticatorInput): Promise<AdminAuthenticatorCatalogRecord> {
    return api.updateAdminAuthenticator(id, input);
  }

  archive(id: string): Promise<void> {
    return api.archiveAdminAuthenticator(id);
  }

  restore(id: string): Promise<void> {
    return api.restoreAdminAuthenticator(id);
  }
}

export class AdminAdapter implements IAdminService {
  public settings: ISettingsService;
  public navigation: IAdminNavigationService;
  public authenticators: IAdminAuthenticatorCatalogService;
  constructor() {
    this.settings = new SettingsAdapter();
    this.navigation = new AdminNavigationAdapter();
    this.authenticators = new AdminAuthenticatorCatalogAdapter();
  }
}

export default new AdminAdapter();
