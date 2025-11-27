import { PetService } from '../services/petService';

describe('PetService (unit)', () => {
  const PET_ID = 'p1';
  const PET_NAME = 'Fido';
  const PET_UPDATED_NAME = 'Fido Updated';
  const mockPrisma: any = {
    pet: {
      findMany: jest.fn().mockResolvedValue([]),
      create: jest.fn().mockResolvedValue({ id: PET_ID, name: PET_NAME }),
      findUnique: jest.fn().mockResolvedValue(null),
      update: jest.fn().mockResolvedValue({ id: PET_ID, name: PET_UPDATED_NAME }),
      delete: jest.fn().mockResolvedValue({ id: PET_ID }),
    },
  };

  const svc = new PetService({ prisma: mockPrisma });

  beforeEach(() => jest.clearAllMocks());

  test('list returns array', async () => {
    const res = await svc.list(10);
    expect(Array.isArray(res)).toBe(true);
    expect(mockPrisma.pet.findMany).toHaveBeenCalledWith({ take: 10 });
  });

  test('create/get/update/delete flow', async () => {
    const created = await svc.create({ name: PET_NAME, species: 'dog' } as any);
    expect(created.id).toBe(PET_ID);
    expect(mockPrisma.pet.create).toHaveBeenCalled();

    mockPrisma.pet.findUnique.mockResolvedValueOnce({ id: PET_ID, name: PET_NAME });
    const got = await svc.getById(PET_ID);
    expect(got).not.toBeNull();

    const updated = await svc.update(PET_ID, { name: PET_UPDATED_NAME } as any);
    expect(updated.name).toBe(PET_UPDATED_NAME);

    const deleted = await svc.delete(PET_ID);
    expect(deleted.id).toBe(PET_ID);
  });
});
