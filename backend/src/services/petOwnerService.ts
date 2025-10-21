import type { PrismaClient, PetOwner, Prisma } from '@prisma/client';
import type { IPetOwnerService } from './interfaces/petOwnerService.interface';

export class PetOwnerService implements IPetOwnerService {
  prisma: PrismaClient;
  constructor(opts: { prisma: PrismaClient }) {
    this.prisma = opts.prisma;
  }

  async list(take = 500): Promise<PetOwner[]> {
    return this.prisma.petOwner.findMany({ take });
  }

  async create(data: Prisma.PetOwnerCreateInput | Prisma.PetOwnerUncheckedCreateInput): Promise<PetOwner> {
    return this.prisma.petOwner.create({ data });
  }

  async getById(id: string): Promise<PetOwner | null> {
    return this.prisma.petOwner.findUnique({ where: { id } });
  }

  async update(id: string, data: Prisma.PetOwnerUpdateInput | Prisma.PetOwnerUncheckedUpdateInput): Promise<PetOwner> {
    return this.prisma.petOwner.update({ where: { id }, data });
  }

  async delete(id: string): Promise<PetOwner> {
    return this.prisma.petOwner.delete({ where: { id } });
  }
}

export default PetOwnerService;
