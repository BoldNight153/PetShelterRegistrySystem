import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import { ensureRoleWithPermissionsForUser } from './helpers/rbac';
import { resetRateLimits } from './helpers/rateLimit';

describe('CRUD routes smoke tests', () => {
  const prisma: any = new PrismaClient();
  const agent = request.agent(app);
  let csrfToken: string | undefined;
  let testEmail: string | undefined;

  beforeAll(async () => {
    await resetRateLimits();
    const csrfRes = await agent.get('/auth/csrf');
    csrfToken = csrfRes.body?.csrfToken;
    testEmail = `crud.${Date.now()}@example.test`;
    const password = 'P@ssw0rd!';
    await agent
      .post('/auth/register')
      .set('x-csrf-token', String(csrfToken))
      .send({ email: testEmail, password, name: 'Crud Tester' });

    const user = await prisma.user.findUnique({ where: { email: String(testEmail) } });
    if (user) {
      await ensureRoleWithPermissionsForUser(prisma, user.id, 'shelter_admin', [
        'owners.write',
        'locations.write',
      ]);
      // tiny delay to ensure write visibility in sqlite
      await new Promise(r => setTimeout(r, 5));
      // fresh login to get clean cookies after role assignment
      const csrf2 = await agent.get('/auth/csrf');
      await resetRateLimits();
      await agent
        .post('/auth/login')
        .set('x-csrf-token', String(csrf2.body?.csrfToken))
        .send({ email: testEmail, password });
    }
  });

  beforeEach(async () => {
    await resetRateLimits();
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });
  let shelterId: string | undefined;
  let locationId: string | undefined;
  let ownerId: string | undefined;

  it('creates a shelter, reads it, updates it and deletes it', async () => {
  const shelterPayload = { name: 'Test Shelter', phone: '555-1212' };
  const createRes = await agent.post('/shelters').send(shelterPayload);
    expect(createRes.status).toBe(201);
    expect(createRes.body).toHaveProperty('id');
    shelterId = createRes.body.id;

  const getRes = await agent.get(`/shelters/${shelterId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.name).toBe(shelterPayload.name);

  const updateRes = await agent.put(`/shelters/${shelterId}`).send({ phone: '555-9999' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.phone).toBe('555-9999');

  const delRes = await agent.delete(`/shelters/${shelterId}`);
    expect(delRes.status).toBe(204);
  });

  it('creates a location for a shelter and updates it', async () => {
    // create shelter first
  const shelterRes = await agent.post('/shelters').send({ name: 'LocShelter' });
    expect(shelterRes.status).toBe(201);
    const sId = shelterRes.body.id;

    const locPayload = { shelterId: sId, code: 'A-1', description: 'Test Cage' };
  const createRes = await agent.post('/locations').send(locPayload);
    expect(createRes.status).toBe(201);
    locationId = createRes.body.id;

  const getRes = await agent.get(`/locations/${locationId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.code).toBe('A-1');

  const updateRes = await agent.put(`/locations/${locationId}`).send({ description: 'Updated' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.description).toBe('Updated');
  });

  it('creates an owner and updates then deletes', async () => {
  const ownerPayload = { firstName: 'Jane', lastName: 'Doe', email: `jane.${Date.now()}@example.test` };
  const createRes = await agent.post('/owners').send(ownerPayload);
    expect(createRes.status).toBe(201);
    ownerId = createRes.body.id;

  const getRes = await agent.get(`/owners/${ownerId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.email).toBe(ownerPayload.email);

  const updateRes = await agent.put(`/owners/${ownerId}`).send({ phone: '800-555-0000' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.phone).toBe('800-555-0000');

    const delRes = await agent.delete(`/owners/${ownerId}`);
    expect(delRes.status).toBe(204);
  });
});
