import type { PrismaClient, Pet, Prisma } from '@prisma/client';
import type IPetService from './interfaces/petService.interface';

export class PetService implements IPetService {
  prisma: PrismaClient;
  constructor(opts: { prisma: PrismaClient }) {
    this.prisma = opts.prisma;
  }

  async list(take = 100): Promise<Pet[]> {
    return this.prisma.pet.findMany({ take });
  }

  async create(data: Prisma.PetCreateInput | Prisma.PetUncheckedCreateInput): Promise<Pet> {
    return this.prisma.pet.create({ data });
  }

  async getById(id: string): Promise<Pet | null> {
    return this.prisma.pet.findUnique({ where: { id } });
  }

  async update(id: string, data: Prisma.PetUpdateInput | Prisma.PetUncheckedUpdateInput): Promise<Pet> {
    return this.prisma.pet.update({ where: { id }, data });
  }

  async delete(id: string): Promise<Pet> {
    return this.prisma.pet.delete({ where: { id } });
  }
}
