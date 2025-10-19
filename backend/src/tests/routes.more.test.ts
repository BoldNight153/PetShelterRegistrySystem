import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import { ensureRoleWithPermissionsForUser } from './helpers/rbac';
// Increase default timeout for this file (integration hooks may take longer)
jest.setTimeout(30000);

describe('More routes integration tests', () => {
  let petId: string | undefined;
  let ownerId: string | undefined;
  let petOwnerId: string | undefined;
  let medicalId: string | undefined;
  let eventId: string | undefined;
  const prisma: any = new PrismaClient();
  const agent = request.agent(app);
  let csrfToken: string | undefined;
  let testEmail: string | undefined;

  beforeAll(async () => {
    const csrfRes = await agent.get('/auth/csrf');
    csrfToken = csrfRes.body?.csrfToken;
    testEmail = `more.${Date.now()}@example.test`;
    const password = 'P@ssw0rd!';
    await agent
      .post('/auth/register')
      .set('x-csrf-token', String(csrfToken))
      .send({ email: testEmail, password, name: 'More Tests' });

    const user = await prisma.user.findUnique({ where: { email: String(testEmail) } });
    if (user) {
      await ensureRoleWithPermissionsForUser(prisma, user.id, 'shelter_admin', [
        'owners.write',
        'locations.write',
        'medical.write',
        'events.write',
      ]);
      await new Promise(r => setTimeout(r, 5));
      const csrf2 = await agent.get('/auth/csrf');
      await agent
        .post('/auth/login')
        .set('x-csrf-token', String(csrf2.body?.csrfToken))
        .send({ email: testEmail, password });
    }
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates a pet and performs related CRUD operations', async () => {
    // create a shelter for the pet
    const shelterRes = await agent.post('/shelters').send({ name: 'PetShelter' });
    expect(shelterRes.status).toBe(201);
    const shelterId = shelterRes.body.id;

    const petPayload = { name: 'Buddy', species: 'dog', shelterId };
    const createRes = await agent.post('/pets').send(petPayload);
    expect(createRes.status).toBe(201);
    petId = createRes.body.id;

    // create an owner
    const ownerRes = await agent.post('/owners').send({ firstName: 'Sam', lastName: 'Smith', email: `sam.${Date.now()}@example.test` });
    expect(ownerRes.status).toBe(201);
    ownerId = ownerRes.body.id;

    // attach owner to pet
    const poRes = await agent.post('/pet-owners').send({ petId, ownerId, role: 'OWNER' });
    expect(poRes.status).toBe(201);
    petOwnerId = poRes.body.id;

    // create a medical record
    const medRes = await agent.post('/medical').send({ petId, vetName: 'Dr Vet', recordType: 'checkup', notes: 'healthy' });
    expect(medRes.status).toBe(201);
    medicalId = medRes.body.id;

    // create an event
    const eventRes = await agent.post('/events').send({ petId, type: 'TRANSFER', notes: 'moved' });
    expect(eventRes.status).toBe(201);
    eventId = eventRes.body.id;

    // cleanup: delete event, medical, pet-owner, owner, pet
    const delEvent = await agent.delete(`/events/${eventId}`);
    expect(delEvent.status).toBe(204);

    const delMed = await agent.delete(`/medical/${medicalId}`);
    expect(delMed.status).toBe(204);

    const delPo = await agent.delete(`/pet-owners/${petOwnerId}`);
    expect(delPo.status).toBe(204);

    const delOwner = await agent.delete(`/owners/${ownerId}`);
    expect(delOwner.status).toBe(204);

    const delPet = await agent.delete(`/pets/${petId}`);
    expect(delPet.status).toBe(204);
  });
});
