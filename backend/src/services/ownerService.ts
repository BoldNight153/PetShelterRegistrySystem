import { PrismaClient } from '@prisma/client';
import { IOwnerService } from './interfaces/ownerService.interface';

export class OwnerService implements IOwnerService {
  private prisma: PrismaClient;
  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  async listOwners(limit = 500) {
    return this.prisma.owner.findMany({ take: limit });
  }

  async createOwner(data: Partial<any>) {
    return this.prisma.owner.create({ data: data as any });
  }

  async getOwner(id: string) {
    return this.prisma.owner.findUnique({ where: { id } });
  }

  async updateOwner(id: string, data: Partial<any>) {
    return this.prisma.owner.update({ where: { id }, data: data as any });
  }

  async deleteOwner(id: string) {
    await this.prisma.owner.delete({ where: { id } });
  }
}

export default OwnerService;
