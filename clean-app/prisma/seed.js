import { PrismaClient } from '@prisma/client'

const prisma = new PrismaClient()

async function main() {
  await prisma.pet.createMany({
    data: [
      { name: 'Rex', type: 'dog', breed: 'labrador', dob: new Date('2022-09-23') },
      { name: 'Fido', type: 'dog', breed: 'poodle', dob: new Date('2024-09-23') },
      { name: 'Mittens', type: 'cat', breed: 'tabby', dob: new Date('2023-09-23') },
    ],
  })
}

main()
  .catch((e) => {
    console.error(e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
