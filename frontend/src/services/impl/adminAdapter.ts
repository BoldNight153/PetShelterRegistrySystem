// Runtime adapter: this file is the runtime boundary and may import runtime-only helpers
// from `frontend/src/lib/api`. UI code should not import types from that module —
// instead use the service interfaces under `services/interfaces`.
import * as api from '../../lib/api';
import type { ISettingsService, IAdminService } from '../interfaces/admin.interface';
import type { JsonValue } from '@/services/interfaces/types';

class SettingsAdapter implements ISettingsService {
  loadSettings(category?: string) {
    return api.loadSettings(category);
  }
  saveSettings(category: string, entries: { key: string; value: JsonValue }[]) {
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
