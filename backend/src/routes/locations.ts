import express from 'express';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { requirePermission } from '../middleware/auth';
import type { Prisma } from '@prisma/client';

type LocationService = {
  list?: (limit?: number) => Promise<unknown[]>;
  create?: (data: any) => Promise<unknown>;
  getById?: (id: string) => Promise<unknown>;
  update?: (id: string, data: any) => Promise<unknown>;
  delete?: (id: string) => Promise<void>;
};

function resolveLocationService(req: any): LocationService | null {
  try { return req.container?.resolve('locationService') as LocationService; } catch { return null; }
}

const router = express.Router();
const LOCATIONS_WRITE_PERMISSION = 'locations.write';

const LocationSchema = z.object({ shelterId: z.string().optional(), code: z.string().min(1), description: z.string().optional(), capacity: z.number().int().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const svc = resolveLocationService(req);
  if (svc?.list) return res.json(await svc.list(500));
  const items = await prisma.location.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission(LOCATIONS_WRITE_PERMISSION), async (req, res) => {
  const parsed = LocationSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  // Build a clean create object without undefined fields so Prisma's XOR types are satisfied
  const { shelterId, code, description, capacity, notes } = parsed.data;
  const createData: any = { code };
  if (shelterId !== undefined) createData.shelterId = shelterId;
  if (description !== undefined) createData.description = description;
  if (capacity !== undefined) createData.capacity = capacity;
  if (notes !== undefined) createData.notes = notes;
  const svc = resolveLocationService(req);
  if (svc?.create) {
    const created = await svc.create(createData);
    return res.status(201).json(created);
  }
  const created = await prisma.location.create({ data: createData as unknown as Prisma.LocationCreateInput });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const svc = resolveLocationService(req);
  const item = svc?.getById ? await svc.getById(id) : await prisma.location.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission(LOCATIONS_WRITE_PERMISSION), async (req, res) => {
  const id = req.params.id;
  const parsed = LocationSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const { shelterId, code, description, capacity, notes } = parsed.data as any;
  const updateData: any = {};
  if (shelterId !== undefined) updateData.shelterId = shelterId;
  if (code !== undefined) updateData.code = code;
  if (description !== undefined) updateData.description = description;
  if (capacity !== undefined) updateData.capacity = capacity;
  if (notes !== undefined) updateData.notes = notes;
  const svc = resolveLocationService(req);
  if (svc?.update) return res.json(await svc.update(id, updateData));
  const updated = await prisma.location.update({ where: { id }, data: updateData as unknown as Prisma.LocationUpdateInput });
  res.json(updated);
});

router.delete('/:id', requirePermission(LOCATIONS_WRITE_PERMISSION), async (req, res) => {
  const id = req.params.id;
  const svc = resolveLocationService(req);
  if (svc?.delete) {
    await svc.delete(id);
    return res.status(204).end();
  }
  await prisma.location.delete({ where: { id } });
  res.status(204).end();
});

export default router;
