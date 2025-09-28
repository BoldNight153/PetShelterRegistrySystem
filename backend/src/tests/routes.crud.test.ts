import request from 'supertest';
import app from '../index';

describe('CRUD routes smoke tests', () => {
  let shelterId: string | undefined;
  let locationId: string | undefined;
  let ownerId: string | undefined;

  it('creates a shelter, reads it, updates it and deletes it', async () => {
    const shelterPayload = { name: 'Test Shelter', phone: '555-1212' };
    const createRes = await request(app).post('/shelters').send(shelterPayload);
    expect(createRes.status).toBe(201);
    expect(createRes.body).toHaveProperty('id');
    shelterId = createRes.body.id;

    const getRes = await request(app).get(`/shelters/${shelterId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.name).toBe(shelterPayload.name);

    const updateRes = await request(app).put(`/shelters/${shelterId}`).send({ phone: '555-9999' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.phone).toBe('555-9999');

    const delRes = await request(app).delete(`/shelters/${shelterId}`);
    expect(delRes.status).toBe(204);
  });

  it('creates a location for a shelter and updates it', async () => {
    // create shelter first
    const shelterRes = await request(app).post('/shelters').send({ name: 'LocShelter' });
    expect(shelterRes.status).toBe(201);
    const sId = shelterRes.body.id;

    const locPayload = { shelterId: sId, code: 'A-1', description: 'Test Cage' };
    const createRes = await request(app).post('/locations').send(locPayload);
    expect(createRes.status).toBe(201);
    locationId = createRes.body.id;

    const getRes = await request(app).get(`/locations/${locationId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.code).toBe('A-1');

    const updateRes = await request(app).put(`/locations/${locationId}`).send({ description: 'Updated' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.description).toBe('Updated');
  });

  it('creates an owner and updates then deletes', async () => {
    const ownerPayload = { firstName: 'Jane', lastName: 'Doe', email: `jane.${Date.now()}@example.test` };
    const createRes = await request(app).post('/owners').send(ownerPayload);
    expect(createRes.status).toBe(201);
    ownerId = createRes.body.id;

    const getRes = await request(app).get(`/owners/${ownerId}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.email).toBe(ownerPayload.email);

    const updateRes = await request(app).put(`/owners/${ownerId}`).send({ phone: '800-555-0000' });
    expect(updateRes.status).toBe(200);
    expect(updateRes.body.phone).toBe('800-555-0000');

    const delRes = await request(app).delete(`/owners/${ownerId}`);
    expect(delRes.status).toBe(204);
  });
});
