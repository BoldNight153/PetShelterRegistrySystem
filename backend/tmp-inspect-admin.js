const { PrismaClient } = require('@prisma/client');

(async () => {
  const prisma = new PrismaClient();
  try {
    const admin = await prisma.user.findUnique({ where: { email: 'admin@example.com' } });
    console.log(admin);
  } catch (err) {
    console.error('Failed to load admin user', err);
  } finally {
    await prisma.$disconnect();
  }
})();
