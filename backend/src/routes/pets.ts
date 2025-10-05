import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { requireRole } from '../middleware/auth';

const router = express.Router();
const prisma = new PrismaClient();

const LocationInput = z.object({ code: z.string().min(1), description: z.string().optional(), shelterId: z.string().optional() });

const PetCreate = z.object({
  name: z.string().min(1),
  species: z.string().min(1),
  breed: z.string().optional(),
  sex: z.enum(['MALE', 'FEMALE', 'UNKNOWN']).optional(),
  dob: z.string().optional(),
  microchip: z.string().optional(),
  shelterId: z.string().optional(),
  locationId: z.string().optional(),
  location: LocationInput.optional()
});

const PetUpdate = PetCreate.partial();

router.get('/', async (req, res) => {
  const pets = await prisma.pet.findMany({ take: 100 });
  res.json(pets);
});

router.post('/', requireRole('staff', 'shelter_admin', 'admin', 'system_admin'), async (req, res) => {
  const parse = PetCreate.safeParse(req.body);
  if (!parse.success) return res.status(400).json({ error: parse.error.format() });

  const data = parse.data;
  const petData: any = {
    name: data.name,
    species: data.species,
    breed: data.breed,
    sex: data.sex,
    dob: data.dob ? new Date(data.dob) : undefined,
    microchip: data.microchip,
    shelterId: data.shelterId
  };

  if (data.locationId) {
    petData.locationId = data.locationId;
  } else if (data.location) {
    petData.location = { create: { code: data.location.code, description: data.location.description, shelterId: data.location.shelterId } };
  }

  const pet = await prisma.pet.create({ data: petData });

  res.status(201).json(pet);
});

router.get('/:id', async (req, res) => {
  const id = req.params.id;
  const pet = await prisma.pet.findUnique({ where: { id } });
  if (!pet) return res.status(404).json({ error: 'not found' });
  res.json(pet);
});

router.put('/:id', requireRole('staff', 'shelter_admin', 'admin', 'system_admin'), async (req, res) => {
  const id = req.params.id;
  const parsed = PetUpdate.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.format() });

  const data = parsed.data;
  const updateData: any = {};
  if (data.name !== undefined) updateData.name = data.name;
  if (data.species !== undefined) updateData.species = data.species;
  if (data.breed !== undefined) updateData.breed = data.breed;
  if (data.sex !== undefined) updateData.sex = data.sex;
  if (data.dob !== undefined) updateData.dob = data.dob ? new Date(data.dob) : null;
  if (data.microchip !== undefined) updateData.microchip = data.microchip;
  if (data.shelterId !== undefined) updateData.shelterId = data.shelterId;
  if (data.locationId !== undefined) updateData.locationId = data.locationId;
  if (data.location !== undefined) {
    // create a nested location if provided
    updateData.location = { create: { code: data.location.code, description: data.location.description, shelterId: data.location.shelterId } };
  }

  try {
    const updated = await prisma.pet.update({ where: { id }, data: updateData });
    res.json(updated);
  } catch (err: any) {
    // Prisma throws when record not found
    if (err.code === 'P2025') return res.status(404).json({ error: 'not found' });
    throw err;
  }
});

router.delete('/:id', requireRole('staff', 'shelter_admin', 'admin', 'system_admin'), async (req, res) => {
  const id = req.params.id;
  try {
    await prisma.pet.delete({ where: { id } });
    res.status(204).end();
  } catch (err: any) {
    if (err.code === 'P2025') return res.status(404).json({ error: 'not found' });
    throw err;
  }
});

export default router;
