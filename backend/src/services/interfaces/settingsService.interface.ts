import { Prisma } from '@prisma/client';

export interface SettingRow {
  id: string;
  category: string;
  key: string;
  value: Prisma.JsonValue;
}

export interface ISettingsService {
  listSettings(category?: string): Promise<Record<string, Record<string, Prisma.JsonValue>>>;
  upsertSettings(category: string, entries: Array<{ key: string; value: Prisma.JsonValue }>, actorId?: string | null): Promise<void>;
}

export default ISettingsService;
