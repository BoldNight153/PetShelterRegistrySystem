import express from 'express';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { IShelterService } from '../services/interfaces/shelterService.interface';
import { requireRole } from '../middleware/auth';

const router = express.Router();

const SHELTER_ROLES = ['shelter_admin', 'admin', 'system_admin'] as const;

const ShelterSchema = z.object({ name: z.string().min(1), address: z.any().optional(), phone: z.string().optional(), email: z.string().email().optional(), capacity: z.number().int().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const maybe = req.container?.resolve?.('shelterService') as IShelterService | undefined;
  if (maybe && typeof maybe.listShelters === 'function') {
    const items = await maybe.listShelters(200);
    return res.json(items);
  }
  const items = await prisma.shelter.findMany({ take: 200 });
  res.json(items);
});

router.post('/', requireRole(...SHELTER_ROLES), async (req, res) => {
  const parsed = ShelterSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const maybe = req.container?.resolve?.('shelterService') as IShelterService | undefined;
  if (maybe && typeof maybe.createShelter === 'function') {
    const created = await maybe.createShelter(parsed.data);
    return res.status(201).json(created);
  }
  const created = await prisma.shelter.create({ data: parsed.data });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const maybe = req.container?.resolve?.('shelterService') as IShelterService | undefined;
  if (maybe && typeof maybe.getShelter === 'function') {
    const item = await maybe.getShelter(id);
    if (!item) return res.status(404).json({ error: 'not found' });
    return res.json(item);
  }
  const item = await prisma.shelter.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requireRole(...SHELTER_ROLES), async (req, res) => {
  const id = req.params.id;
  const parsed = ShelterSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const maybe = req.container?.resolve?.('shelterService') as IShelterService | undefined;
  if (maybe && typeof maybe.updateShelter === 'function') {
    const updated = await maybe.updateShelter(id, parsed.data);
    return res.json(updated);
  }
  const updated = await prisma.shelter.update({ where: { id }, data: parsed.data });
  res.json(updated);
});

router.delete('/:id', requireRole(...SHELTER_ROLES), async (req, res) => {
  const id = req.params.id;
  const maybe = req.container?.resolve?.('shelterService') as IShelterService | undefined;
  if (maybe && typeof maybe.deleteShelter === 'function') {
    await maybe.deleteShelter(id);
    return res.status(204).end();
  }
  await prisma.shelter.delete({ where: { id } });
  res.status(204).end();
});

export default router;
