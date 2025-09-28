import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()

async function main() {
  await prisma.pet.createMany({
    data: [
      { name: 'Rex', dob: new Date('2022-09-23'), type: 'dog', breed: 'labrador' },
      { name: 'Fido', dob: new Date('2024-09-23'), type: 'dog', breed: 'poodle' },
      { name: 'Mittens', dob: new Date('2023-09-23'), type: 'cat', breed: 'tabby' },
    ],
    skipDuplicates: true,
  })
}

main()
  .catch(e => console.error(e))
  .finally(async () => {
    await prisma.$disconnect()
  })
