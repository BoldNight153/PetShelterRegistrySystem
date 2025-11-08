const { PrismaClient } = require('@prisma/client');
(async () => {
  const p = new PrismaClient();
  try {
    const m = await p.menu.findUnique({ where: { name: 'main' }, include: { items: true } });
    console.log('menu:', JSON.stringify(m, null, 2));
  } catch (err) {
    console.error('error querying menu:', err);
    process.exitCode = 1;
  } finally {
    await p.$disconnect();
  }
})();
