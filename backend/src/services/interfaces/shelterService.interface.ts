import type { Prisma } from '@prisma/client';

export interface ShelterRow {
  id: string;
  name: string;
  address?: Prisma.JsonValue;
  phone?: string | null;
  email?: string | null;
  capacity?: number | null;
  notes?: string | null;
}

export interface IShelterService {
  listShelters(limit?: number): Promise<ShelterRow[]>;
  createShelter(data: Prisma.ShelterCreateInput | Prisma.ShelterUncheckedCreateInput): Promise<ShelterRow>;
  getShelter(id: string): Promise<ShelterRow | null>;
  updateShelter(id: string, data: Prisma.ShelterUpdateInput | Prisma.ShelterUncheckedUpdateInput): Promise<ShelterRow>;
  deleteShelter(id: string): Promise<void>;
}

export default IShelterService;
