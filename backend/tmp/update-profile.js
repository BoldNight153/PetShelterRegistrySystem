require('ts-node/register/transpile-only');
const request = require('supertest');
const { PrismaClient } = require('@prisma/client');
const app = require('../src/index').default;

const prisma = new PrismaClient();

(async () => {
  const csrfRes = await request(app).get('/auth/csrf');
  const csrfToken = csrfRes.body.csrfToken;
  const csrfCookie = csrfRes.headers['set-cookie'].find((c) => c.startsWith('csrfToken='));

  const unique = Date.now();
  const email = `profile-${unique}@example.com`;
  const registerRes = await request(app)
    .post('/auth/register')
    .set('x-csrf-token', csrfToken)
    .set('Cookie', csrfCookie)
    .send({ email, password: 'Test1234!', name: 'Test User' });

  const userId = registerRes.body?.id;
  if (userId) {
    await prisma.user.update({ where: { id: userId }, data: { emailVerified: new Date() } });
  }

  const csrf2 = await request(app).get('/auth/csrf');
  const csrfToken2 = csrf2.body.csrfToken;
  const csrfCookie2 = csrf2.headers['set-cookie'].find((c) => c.startsWith('csrfToken='));

  const loginRes = await request(app)
    .post('/auth/login')
    .set('x-csrf-token', csrfToken2)
    .set('Cookie', csrfCookie2)
    .send({ email, password: 'Test1234!' });

  const cookies = loginRes.headers['set-cookie'] || [];
  const authCookies = cookies
    .filter(Boolean)
    .map((c) => c.split(';')[0])
    .join('; ');

  const csrf3 = await request(app).get('/auth/csrf');
  const csrfToken3 = csrf3.body.csrfToken;
  const csrfCookie3 = csrf3.headers['set-cookie'].find((c) => c.startsWith('csrfToken='));
  const cookieHeader = [authCookies, csrfCookie3?.split(';')[0]].filter(Boolean).join('; ');

  const update = await request(app)
    .put('/auth/me')
    .set('x-csrf-token', csrfToken3)
    .set('Cookie', cookieHeader)
    .send({ name: 'Updated User', title: 'Director' });

  console.log('update status', update.status, update.body);
  await prisma.$disconnect();
  process.exit(0);
})();
