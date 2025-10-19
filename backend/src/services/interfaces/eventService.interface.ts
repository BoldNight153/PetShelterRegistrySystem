import type { Event, Prisma } from '@prisma/client';

export interface IEventService {
  list(take?: number): Promise<Event[]>;
  create(data: Prisma.EventCreateInput | Prisma.EventUncheckedCreateInput): Promise<Event>;
  getById(id: string): Promise<Event | null>;
  update(id: string, data: Prisma.EventUpdateInput | Prisma.EventUncheckedUpdateInput): Promise<Event>;
  delete(id: string): Promise<Event>;
}

export default IEventService;
