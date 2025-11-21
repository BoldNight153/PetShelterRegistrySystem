const { PrismaClient } = require('@prisma/client');
const argon2 = require('argon2');
(async () => {
  const prisma = new PrismaClient();
  const hash = await argon2.hash('Admin123!@#', { type: argon2.argon2id });
  await prisma.user.update({ where: { email: 'admin@example.com' }, data: { passwordHash: hash } });
  await prisma.$disconnect();
  console.log('updated');
})();
