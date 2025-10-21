import { PetService } from '../services/petService';

describe('PetService (unit)', () => {
  const now = new Date();
  const mockPrisma: any = {
    pet: {
      findMany: jest.fn().mockResolvedValue([]),
      create: jest.fn().mockResolvedValue({ id: 'p1', name: 'Fido' }),
      findUnique: jest.fn().mockResolvedValue(null),
      update: jest.fn().mockResolvedValue({ id: 'p1', name: 'Fido Updated' }),
      delete: jest.fn().mockResolvedValue({ id: 'p1' }),
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
    const created = await svc.create({ name: 'Fido', species: 'dog' } as any);
    expect(created.id).toBe('p1');
    expect(mockPrisma.pet.create).toHaveBeenCalled();

    mockPrisma.pet.findUnique.mockResolvedValueOnce({ id: 'p1', name: 'Fido' });
    const got = await svc.getById('p1');
    expect(got).not.toBeNull();

    const updated = await svc.update('p1', { name: 'Fido Updated' } as any);
    expect(updated.name).toBe('Fido Updated');

    const deleted = await svc.delete('p1');
    expect(deleted.id).toBe('p1');
  });
});
