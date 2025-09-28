import prisma from '../db/index.js'

export async function listPets(req, res) {
  const pets = await prisma.pet.findMany()
  res.json(pets)
}

export async function getPet(req, res) {
  const id = Number(req.params.id)
  const pet = await prisma.pet.findUnique({ where: { id } })
  if (!pet) return res.status(404).json({ error: 'Not found' })
  res.json(pet)
}
