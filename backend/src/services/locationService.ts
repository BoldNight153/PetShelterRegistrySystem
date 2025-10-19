import type { PrismaClient, Location, Prisma } from '@prisma/client';
import type { ILocationService } from './interfaces/locationService.interface';

export class LocationService implements ILocationService {
  prisma: PrismaClient;
  constructor(opts: { prisma: PrismaClient }) {
    this.prisma = opts.prisma;
  }

  async list(take = 500): Promise<Location[]> {
    return this.prisma.location.findMany({ take });
  }

  async create(data: Prisma.LocationCreateInput | Prisma.LocationUncheckedCreateInput): Promise<Location> {
    return this.prisma.location.create({ data });
  }

  async getById(id: string): Promise<Location | null> {
    return this.prisma.location.findUnique({ where: { id } });
  }

  async update(id: string, data: Prisma.LocationUpdateInput | Prisma.LocationUncheckedUpdateInput): Promise<Location> {
    return this.prisma.location.update({ where: { id }, data });
  }

  async delete(id: string): Promise<Location> {
    return this.prisma.location.delete({ where: { id } });
  }
}

export default LocationService;
