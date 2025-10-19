import type { SettingsMap, JsonValue } from '../../lib/api';

export interface ISettingsService {
  loadSettings(category?: string): Promise<SettingsMap>;
  saveSettings(category: string, entries: { key: string; value: JsonValue }[]): Promise<unknown>;
}

export interface IAdminService {
  settings: ISettingsService;
}
