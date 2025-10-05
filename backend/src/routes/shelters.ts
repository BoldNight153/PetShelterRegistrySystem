import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { requireRole } from '../middleware/auth';

const router = express.Router();
const prisma = new PrismaClient();

const ShelterSchema = z.object({ name: z.string().min(1), address: z.any().optional(), phone: z.string().optional(), email: z.string().email().optional(), capacity: z.number().int().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const items = await prisma.shelter.findMany({ take: 200 });
  res.json(items);
});

router.post('/', requireRole('shelter_admin', 'admin', 'system_admin'), async (req, res) => {
  const parsed = ShelterSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const created = await prisma.shelter.create({ data: parsed.data });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const item = await prisma.shelter.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requireRole('shelter_admin', 'admin', 'system_admin'), async (req, res) => {
  const id = req.params.id;
  const parsed = ShelterSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const updated = await prisma.shelter.update({ where: { id }, data: parsed.data });
  res.json(updated);
});

router.delete('/:id', requireRole('shelter_admin', 'admin', 'system_admin'), async (req, res) => {
  const id = req.params.id;
  await prisma.shelter.delete({ where: { id } });
  res.status(204).end();
});

export default router;
