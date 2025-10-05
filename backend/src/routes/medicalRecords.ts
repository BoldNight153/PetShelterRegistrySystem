import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { requirePermission } from '../middleware/auth';

const router = express.Router();
const prisma = new PrismaClient();

const MedicalSchema = z.object({ petId: z.string(), visitDate: z.string().optional(), vetName: z.string().optional(), recordType: z.string().optional(), notes: z.string().optional(), files: z.any().optional() });

router.get('/', async (req, res) => {
  const items = await prisma.medicalRecord.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission('medical.write'), async (req, res) => {
  const parsed = MedicalSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const created = await prisma.medicalRecord.create({ data: { petId: data.petId, visitDate: data.visitDate ? new Date(data.visitDate) : undefined, vetName: data.vetName, recordType: data.recordType, notes: data.notes, files: data.files } });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const item = await prisma.medicalRecord.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission('medical.write'), async (req, res) => {
  const id = req.params.id;
  const parsed = MedicalSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const updated = await prisma.medicalRecord.update({ where: { id }, data: parsed.data });
  res.json(updated);
});

router.delete('/:id', requirePermission('medical.write'), async (req, res) => {
  const id = req.params.id;
  await prisma.medicalRecord.delete({ where: { id } });
  res.status(204).end();
});

export default router;
