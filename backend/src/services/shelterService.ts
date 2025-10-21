import { PrismaClient } from '@prisma/client';
import { IShelterService } from './interfaces/shelterService.interface';

export class ShelterService implements IShelterService {
  private prisma: PrismaClient;
  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  async listShelters(limit = 200) {
    return this.prisma.shelter.findMany({ take: limit });
  }

  async createShelter(data: Partial<any>) {
    return this.prisma.shelter.create({ data: data as any });
  }

  async getShelter(id: string) {
    return this.prisma.shelter.findUnique({ where: { id } });
  }

  async updateShelter(id: string, data: Partial<any>) {
    return this.prisma.shelter.update({ where: { id }, data: data as any });
  }

  async deleteShelter(id: string) {
    await this.prisma.shelter.delete({ where: { id } });
  }
}

export default ShelterService;
