import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { requirePermission } from '../middleware/auth';

const router = express.Router();
const prisma = new PrismaClient();

const OwnerSchema = z.object({ firstName: z.string().min(1), lastName: z.string().min(1), email: z.string().email().optional(), phone: z.string().optional(), type: z.string().optional(), address: z.any().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const items = await prisma.owner.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission('owners.write'), async (req, res) => {
  const parsed = OwnerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const created = await prisma.owner.create({ data: parsed.data });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const item = await prisma.owner.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission('owners.write'), async (req, res) => {
  const id = req.params.id;
  const parsed = OwnerSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const updated = await prisma.owner.update({ where: { id }, data: parsed.data });
  res.json(updated);
});

router.delete('/:id', requirePermission('owners.write'), async (req, res) => {
  const id = req.params.id;
  await prisma.owner.delete({ where: { id } });
  res.status(204).end();
});

export default router;
