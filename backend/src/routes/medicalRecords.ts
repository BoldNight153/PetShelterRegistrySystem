import express from 'express';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { requirePermission } from '../middleware/auth';

function resolveMedicalService(req: any) {
  try { return req.container?.resolve('medicalRecordService'); } catch { return null; }
}

const router = express.Router();

const MedicalSchema = z.object({ petId: z.string(), visitDate: z.string().optional(), vetName: z.string().optional(), recordType: z.string().optional(), notes: z.string().optional(), files: z.any().optional() });

router.get('/', async (req, res) => {
  const svc = resolveMedicalService(req);
  if (svc) return res.json(await svc.list(500));
  const items = await prisma.medicalRecord.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission('medical.write'), async (req, res) => {
  const parsed = MedicalSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const svc = resolveMedicalService(req);
  const payload: any = { petId: data.petId, visitDate: data.visitDate ? new Date(data.visitDate) : undefined, vetName: data.vetName, recordType: data.recordType, notes: data.notes, files: data.files };
  if (svc) {
    const created = await svc.create(payload);
    return res.status(201).json(created);
  }
  const created = await prisma.medicalRecord.create({ data: payload });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const svc = resolveMedicalService(req);
  const item = svc ? await svc.getById(id) : await prisma.medicalRecord.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission('medical.write'), async (req, res) => {
  const id = req.params.id;
  const parsed = MedicalSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const svc = resolveMedicalService(req);
  if (svc) return res.json(await svc.update(id, parsed.data));
  const updated = await prisma.medicalRecord.update({ where: { id }, data: parsed.data });
  res.json(updated);
});

router.delete('/:id', requirePermission('medical.write'), async (req, res) => {
  const id = req.params.id;
  const svc = resolveMedicalService(req);
  if (svc) {
    await svc.delete(id);
    return res.status(204).end();
  }
  await prisma.medicalRecord.delete({ where: { id } });
  res.status(204).end();
});

export default router;
