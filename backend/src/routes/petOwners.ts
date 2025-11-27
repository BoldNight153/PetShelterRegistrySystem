import express from 'express';
import { z } from 'zod';
import { prismaClient as prisma } from '../prisma/client';
import { requirePermission } from '../middleware/auth';

function resolvePetOwnerService(req: any) {
  try { return req.container?.resolve?.('petOwnerService') as import('../services/petOwnerService').PetOwnerService | null; } catch { return null; }
}

const router = express.Router();
const OWNERS_WRITE_PERMISSION = 'owners.write';

const PetOwnerSchema = z.object({ petId: z.string(), ownerId: z.string(), role: z.enum(['OWNER','FOSTER','EMERGENCY_CONTACT']).optional(), isPrimary: z.boolean().optional(), startDate: z.string().optional(), endDate: z.string().optional(), notes: z.string().optional() });

router.get('/', async (req, res) => {
  const svc = resolvePetOwnerService(req);
  if (svc) return res.json(await svc.list(500));
  const items = await prisma.petOwner.findMany({ take: 500 });
  res.json(items);
});

router.post('/', requirePermission(OWNERS_WRITE_PERMISSION), async (req, res) => {
  const parsed = PetOwnerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const svc = resolvePetOwnerService(req);
  const createPayload: import('@prisma/client').Prisma.PetOwnerCreateInput | import('@prisma/client').Prisma.PetOwnerUncheckedCreateInput = {
    petId: data.petId,
    ownerId: data.ownerId,
    role: data.role as any,
    isPrimary: data.isPrimary,
    startDate: data.startDate ? new Date(data.startDate) : undefined,
    endDate: data.endDate ? new Date(data.endDate) : undefined,
    notes: data.notes,
  };
  if (svc) {
    const created = await svc.create(createPayload);
    return res.status(201).json(created);
  }
  const created = await prisma.petOwner.create({ data: createPayload });
  res.status(201).json(created);
});

router.get('/:id', async (req, res) => {
  const { id } = req.params as { id: string };
  const svc = resolvePetOwnerService(req);
  const item = svc ? await svc.getById(id) : await prisma.petOwner.findUnique({ where: { id } });
  if (!item) return res.status(404).json({ error: 'not found' });
  res.json(item);
});

router.put('/:id', requirePermission(OWNERS_WRITE_PERMISSION), async (req, res) => {
  const { id } = req.params as { id: string };
  const parsed = PetOwnerSchema.partial().safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });
  const data = parsed.data;
  const svc = resolvePetOwnerService(req);
  const payload: import('@prisma/client').Prisma.PetOwnerUpdateInput | import('@prisma/client').Prisma.PetOwnerUncheckedUpdateInput = {
    ...data,
    startDate: data.startDate ? new Date(data.startDate) : undefined,
    endDate: data.endDate ? new Date(data.endDate) : undefined,
  } as any;
  if (svc) return res.json(await svc.update(id, payload));
  const updated = await prisma.petOwner.update({ where: { id }, data: payload });
  res.json(updated);
});

router.delete('/:id', requirePermission(OWNERS_WRITE_PERMISSION), async (req, res) => {
  const id = req.params.id;
  const svc = resolvePetOwnerService(req);
  if (svc) {
    await svc.delete(id);
    return res.status(204).end();
  }
  await prisma.petOwner.delete({ where: { id } });
  res.status(204).end();
});

export default router;
