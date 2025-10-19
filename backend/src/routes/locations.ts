import express from 'express';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { requirePermission } from '../middleware/auth';

function resolveLocationService(req: any) {
  try { return req.container?.resolve('locationService'); } catch { return null; }
}

const router = express.Router();

const LocationSchema = z.object({ shelterId: z.string().optional(), code: z.string().min(1), description: z.string().optional(), capacity: z.number().int().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const svc = resolveLocationService(req);
  if (svc) return res.json(await svc.list(500));
  const items = await prisma.location.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission('locations.write'), async (req, res) => {
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
  if (svc) {
    const created = await svc.create(createData);
    return res.status(201).json(created);
  }
  const created = await prisma.location.create({ data: createData });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const svc = resolveLocationService(req);
  const item = svc ? await svc.getById(id) : await prisma.location.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission('locations.write'), async (req, res) => {
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
  if (svc) return res.json(await svc.update(id, updateData));
  const updated = await prisma.location.update({ where: { id }, data: updateData });
  res.json(updated);
});

router.delete('/:id', requirePermission('locations.write'), async (req, res) => {
  const id = req.params.id;
  const svc = resolveLocationService(req);
  if (svc) {
    await svc.delete(id);
    return res.status(204).end();
  }
  await prisma.location.delete({ where: { id } });
  res.status(204).end();
});

export default router;
