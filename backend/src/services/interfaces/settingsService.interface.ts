import { Prisma } from '@prisma/client';

export interface SettingRow {
  id: string;
  category: string;
  key: string;
  value: Prisma.JsonValue;
}

type ListSettingsOptions = {
  preserveUnknownAuth?: boolean;
};

export interface ISettingsService {
  listSettings(category?: string, options?: ListSettingsOptions): Promise<Record<string, Record<string, Prisma.JsonValue>>>;
  upsertSettings(category: string, entries: Array<{ key: string; value: Prisma.JsonValue }>, actorId?: string | null): Promise<void>;
}

export default ISettingsService;
export type { ListSettingsOptions };
