import type { Location, Prisma } from '@prisma/client';

export interface ILocationService {
  list(take?: number): Promise<Location[]>;
  create(data: Prisma.LocationCreateInput | Prisma.LocationUncheckedCreateInput): Promise<Location>;
  getById(id: string): Promise<Location | null>;
  update(id: string, data: Prisma.LocationUpdateInput | Prisma.LocationUncheckedUpdateInput): Promise<Location>;
  delete(id: string): Promise<Location>;
}

export default ILocationService;
