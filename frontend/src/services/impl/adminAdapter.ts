import * as api from '../../lib/api';
import type { ISettingsService, IAdminService } from '../interfaces/admin.interface';

class SettingsAdapter implements ISettingsService {
  loadSettings(category?: string) {
    return api.loadSettings(category);
  }
  saveSettings(category: string, entries: { key: string; value: api.JsonValue }[]) {
    return api.saveSettings(category, entries);
  }
}

export class AdminAdapter implements IAdminService {
  public settings: ISettingsService;
  constructor() {
    this.settings = new SettingsAdapter();
  }
}

export default new AdminAdapter();
