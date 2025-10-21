import type { SettingsMap, JsonValue } from './types';
export type { SettingsMap, JsonValue };

export interface ISettingsService {
  loadSettings(category?: string): Promise<SettingsMap>;
  saveSettings(category: string, entries: { key: string; value: JsonValue }[]): Promise<unknown>;
}

export interface IAdminService {
  settings: ISettingsService;
}
