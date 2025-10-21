import type { PrismaClient, Event, Prisma } from '@prisma/client';
import type { IEventService } from './interfaces/eventService.interface';

export class EventService implements IEventService {
  prisma: PrismaClient;
  constructor(opts: { prisma: PrismaClient }) {
    this.prisma = opts.prisma;
  }

  async list(take = 500): Promise<Event[]> {
    return this.prisma.event.findMany({ take });
  }

  async create(data: Prisma.EventCreateInput | Prisma.EventUncheckedCreateInput): Promise<Event> {
    return this.prisma.event.create({ data });
  }

  async getById(id: string): Promise<Event | null> {
    return this.prisma.event.findUnique({ where: { id } });
  }

  async update(id: string, data: Prisma.EventUpdateInput | Prisma.EventUncheckedUpdateInput): Promise<Event> {
    return this.prisma.event.update({ where: { id }, data });
  }

  async delete(id: string): Promise<Event> {
    return this.prisma.event.delete({ where: { id } });
  }
}

export default EventService;
