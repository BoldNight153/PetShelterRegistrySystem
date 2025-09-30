import request from 'supertest';
import app from '../index';

describe('More routes integration tests', () => {
  let petId: string | undefined;
  let ownerId: string | undefined;
  let petOwnerId: string | undefined;
  let medicalId: string | undefined;
  let eventId: string | undefined;

  it('creates a pet and performs related CRUD operations', async () => {
    // create a shelter for the pet
    const shelterRes = await request(app).post('/shelters').send({ name: 'PetShelter' });
    expect(shelterRes.status).toBe(201);
    const shelterId = shelterRes.body.id;

    const petPayload = { name: 'Buddy', species: 'dog', shelterId };
    const createRes = await request(app).post('/pets').send(petPayload);
    expect(createRes.status).toBe(201);
    petId = createRes.body.id;

    // create an owner
    const ownerRes = await request(app).post('/owners').send({ firstName: 'Sam', lastName: 'Smith', email: `sam.${Date.now()}@example.test` });
    expect(ownerRes.status).toBe(201);
    ownerId = ownerRes.body.id;

    // attach owner to pet
    const poRes = await request(app).post('/pet-owners').send({ petId, ownerId, role: 'OWNER' });
    expect(poRes.status).toBe(201);
    petOwnerId = poRes.body.id;

    // create a medical record
    const medRes = await request(app).post('/medical').send({ petId, vetName: 'Dr Vet', recordType: 'checkup', notes: 'healthy' });
    expect(medRes.status).toBe(201);
    medicalId = medRes.body.id;

    // create an event
    const eventRes = await request(app).post('/events').send({ petId, type: 'TRANSFER', notes: 'moved' });
    expect(eventRes.status).toBe(201);
    eventId = eventRes.body.id;

    // cleanup: delete event, medical, pet-owner, owner, pet
    const delEvent = await request(app).delete(`/events/${eventId}`);
    expect(delEvent.status).toBe(204);

    const delMed = await request(app).delete(`/medical/${medicalId}`);
    expect(delMed.status).toBe(204);

    const delPo = await request(app).delete(`/pet-owners/${petOwnerId}`);
    expect(delPo.status).toBe(204);

    const delOwner = await request(app).delete(`/owners/${ownerId}`);
    expect(delOwner.status).toBe(204);

    const delPet = await request(app).delete(`/pets/${petId}`);
    expect(delPet.status).toBe(204);
  });
});
