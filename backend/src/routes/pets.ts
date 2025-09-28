import express from 'express';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';

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

router.get('/', async (req, res) => {
  const pets = await prisma.pet.findMany({ take: 100 });
  res.json(pets);
});

router.post('/', async (req, res) => {
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

export default router;
