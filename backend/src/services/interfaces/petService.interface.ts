import type { Pet, Prisma } from '@prisma/client';

export interface IPetService {
  list(take?: number): Promise<Pet[]>;
  create(data: Prisma.PetCreateInput | Prisma.PetUncheckedCreateInput): Promise<Pet>;
  getById(id: string): Promise<Pet | null>;
  update(id: string, data: Prisma.PetUpdateInput | Prisma.PetUncheckedUpdateInput): Promise<Pet>;
  delete(id: string): Promise<Pet>;
}

export default IPetService;
