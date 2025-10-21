import { UserService } from '../services/userService';

jest.mock('@prisma/client', () => {
  const m = {
    PrismaClient: jest.fn().mockImplementation(() => ({
      user: {
        count: jest.fn().mockResolvedValue(1),
        findMany: jest.fn().mockResolvedValue([
          { id: 'u1', email: 'a@b.com', name: 'Alice', roles: [{ role: { name: 'admin' } }], locks: [] },
        ]),
        findUnique: jest.fn().mockImplementation(({ where }) => {
          if (where.id === 'u1') return Promise.resolve({ id: 'u1', email: 'a@b.com', name: 'Alice', roles: [{ role: { name: 'admin' } }], locks: [], createdAt: new Date(), lastLoginAt: null, metadata: null });
          return Promise.resolve(null);
        }),
      },
      userLock: {
        create: jest.fn().mockResolvedValue({ id: 'lock1', userId: 'u1', reason: 'test', lockedAt: new Date() }),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      userRole: { upsert: jest.fn().mockResolvedValue({ userId: 'u1', roleId: 'r1' }), delete: jest.fn().mockResolvedValue({}) },
      refreshToken: { updateMany: jest.fn().mockResolvedValue({ count: 1 }) },
      role: { findUnique: jest.fn().mockImplementation(({ where }) => {
        if (where?.name === 'admin') return Promise.resolve({ id: 'r1', name: 'admin' });
        return Promise.resolve(null);
      }) },
    })),
  };
  return m;
});

describe('UserService', () => {
  let s: UserService;
  beforeEach(() => {
    s = new UserService();
  });

  test('searchUsers returns shaped data', async () => {
    const res = await s.searchUsers('alice', 1, 10);
    expect(res.total).toBe(1);
    expect(res.items[0].id).toBe('u1');
    expect(res.items[0].roles).toEqual(['admin']);
  });

  test('getUser returns null when not found', async () => {
    const u = await s.getUser('missing');
    expect(u).toBeNull();
  });

  test('assignRole and revokeRole behave as expected', async () => {
    const assigned = await s.assignRole('u1', 'admin');
    expect(assigned).toBeDefined();
    const revoked = await s.revokeRole('u1', 'admin');
    expect(revoked).toBe(true);
  });

  test('lockUser and unlockUser work', async () => {
    const lock = await s.lockUser('u1', { reason: 'test', expiresAt: null, notes: null, actorId: 'admin' });
    expect(lock).toBeDefined();
    await expect(s.unlockUser('u1', { actorId: 'admin', notes: 'ok' })).resolves.toBeUndefined();
  });
});
