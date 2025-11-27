import express from 'express';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { requirePermission } from '../middleware/auth';
import type { Prisma } from '@prisma/client';

type EventService = {
  list?: (limit?: number) => Promise<unknown[]>;
  create?: (data: any) => Promise<unknown>;
  getById?: (id: string) => Promise<unknown>;
  update?: (id: string, data: any) => Promise<unknown>;
  delete?: (id: string) => Promise<void>;
};

function resolveEventService(req: any): EventService | null {
  try { return req.container?.resolve('eventService') as EventService; } catch { return null; }
}

const router = express.Router();
const EVENTS_WRITE_PERMISSION = 'events.write';

const EventSchema = z.object({ petId: z.string(), type: z.string(), occurredAt: z.string().optional(), fromShelterId: z.string().optional(), toShelterId: z.string().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const svc = resolveEventService(req);
  if (svc?.list) return res.json(await svc.list(500));
  const items = await prisma.event.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission(EVENTS_WRITE_PERMISSION), async (req, res) => {
  const parsed = EventSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const svc = resolveEventService(req);
  const payload = { petId: data.petId, type: data.type, occurredAt: data.occurredAt ? new Date(data.occurredAt) : undefined, fromShelterId: data.fromShelterId, toShelterId: data.toShelterId, notes: data.notes };
  if (svc?.create) {
    const created = await svc.create(payload);
    return res.status(201).json(created);
  }
  const created = await prisma.event.create({ data: payload as unknown as Prisma.EventCreateInput });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const svc = resolveEventService(req);
  const item = svc?.getById ? await svc.getById(id) : await prisma.event.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission(EVENTS_WRITE_PERMISSION), async (req, res) => {
  const id = req.params.id;
  const parsed = EventSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const svc = resolveEventService(req);
  if (svc?.update) return res.json(await svc.update(id, parsed.data));
  const updated = await prisma.event.update({ where: { id }, data: parsed.data as unknown as Prisma.EventUpdateInput });
  res.json(updated);
});

router.delete('/:id', requirePermission(EVENTS_WRITE_PERMISSION), async (req, res) => {
  const id = req.params.id;
  const svc = resolveEventService(req);
  if (svc?.delete) {
    await svc.delete(id);
    return res.status(204).end();
  }
  await prisma.event.delete({ where: { id } });
  res.status(204).end();
});

export default router;
