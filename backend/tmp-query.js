const { PrismaClient } = require('@prisma/client');
(async () => {
  const prisma = new PrismaClient();
  const user = await prisma.user.findUnique({ where: { email: 'admin@example.com' } });
  console.log('user', user);
  if (user) {
    const factors = await prisma.userMfaFactor.findMany({ where: { userId: user.id } });
    console.log('factors', factors);
    const devices = await prisma.userDevice.findMany({ where: { userId: user.id } });
    console.log('devices', devices);
    const locks = await prisma.userLock.findMany({ where: { userId: user.id, unlockedAt: null } });
    console.log('locks', locks);
  }
  await prisma.$disconnect();
})().catch(err => {
  console.error(err);
  process.exit(1);
});
