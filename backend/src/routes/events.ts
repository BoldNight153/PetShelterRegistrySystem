import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { requirePermission } from '../middleware/auth';

const router = express.Router();
const prisma = new PrismaClient();

const EventSchema = z.object({ petId: z.string(), type: z.string(), occurredAt: z.string().optional(), fromShelterId: z.string().optional(), toShelterId: z.string().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const items = await prisma.event.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission('events.write'), async (req, res) => {
  const parsed = EventSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const created = await prisma.event.create({ data: { petId: data.petId, type: data.type, occurredAt: data.occurredAt ? new Date(data.occurredAt) : undefined, fromShelterId: data.fromShelterId, toShelterId: data.toShelterId, notes: data.notes } });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const item = await prisma.event.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission('events.write'), async (req, res) => {
  const id = req.params.id;
  const parsed = EventSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const updated = await prisma.event.update({ where: { id }, data: parsed.data });
  res.json(updated);
});

router.delete('/:id', requirePermission('events.write'), async (req, res) => {
  const id = req.params.id;
  await prisma.event.delete({ where: { id } });
  res.status(204).end();
});

export default router;
