import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { requirePermission } from '../middleware/auth';

const router = express.Router();
const prisma = new PrismaClient();

const PetOwnerSchema = z.object({ petId: z.string(), ownerId: z.string(), role: z.enum(['OWNER','FOSTER','EMERGENCY_CONTACT']).optional(), isPrimary: z.boolean().optional(), startDate: z.string().optional(), endDate: z.string().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const items = await prisma.petOwner.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission('owners.write'), async (req, res) => {
  const parsed = PetOwnerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const created = await prisma.petOwner.create({ data: { petId: data.petId, ownerId: data.ownerId, role: data.role as any, isPrimary: data.isPrimary, startDate: data.startDate ? new Date(data.startDate) : undefined, endDate: data.endDate ? new Date(data.endDate) : undefined, notes: data.notes } });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const item = await prisma.petOwner.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission('owners.write'), async (req, res) => {
  const id = req.params.id;
  const parsed = PetOwnerSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const updated = await prisma.petOwner.update({ where: { id }, data: { ...data, startDate: data.startDate ? new Date(data.startDate) : undefined, endDate: data.endDate ? new Date(data.endDate) : undefined } as any });
  res.json(updated);
});

router.delete('/:id', requirePermission('owners.write'), async (req, res) => {
  const id = req.params.id;
  await prisma.petOwner.delete({ where: { id } });
  res.status(204).end();
});

export default router;
