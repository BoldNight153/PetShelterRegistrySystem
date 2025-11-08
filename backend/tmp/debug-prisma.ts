import { PrismaClient } from '@prisma/client';

async function main() {
  const prisma = new PrismaClient();
  await prisma.$connect();
  const shelter = await prisma.shelter.create({ data: { name: 'Debug Shelter' } });
  console.log('shelter', shelter.id);
  const pet = await prisma.pet.create({ data: { name: 'Buddy', species: 'dog', shelterId: shelter.id } });
  console.log('pet', pet.id);
  await prisma.$disconnect();
}

main().catch(err => {
  console.error('error', err);
  process.exit(1);
});
