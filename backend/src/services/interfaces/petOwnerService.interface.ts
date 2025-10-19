import type { PetOwner, Prisma } from '@prisma/client';

export interface IPetOwnerService {
  list(take?: number): Promise<PetOwner[]>;
  create(data: Prisma.PetOwnerCreateInput | Prisma.PetOwnerUncheckedCreateInput): Promise<PetOwner>;
  getById(id: string): Promise<PetOwner | null>;
  update(id: string, data: Prisma.PetOwnerUpdateInput | Prisma.PetOwnerUncheckedUpdateInput): Promise<PetOwner>;
  delete(id: string): Promise<PetOwner>;
}

export default IPetOwnerService;
