import type { Owner, Prisma } from '@prisma/client';

export interface IOwnerService {
  listOwners(limit?: number): Promise<Owner[]>;
  createOwner(data: Prisma.OwnerCreateInput | Prisma.OwnerUncheckedCreateInput): Promise<Owner>;
  getOwner(id: string): Promise<Owner | null>;
  updateOwner(id: string, data: Prisma.OwnerUpdateInput | Prisma.OwnerUncheckedUpdateInput): Promise<Owner>;
  deleteOwner(id: string): Promise<void>;
}

export default IOwnerService;
