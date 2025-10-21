import { RoleService } from '../services/roleService';
import { PrismaClient } from '@prisma/client';

jest.mock('@prisma/client', () => {
  const m = {
    PrismaClient: jest.fn().mockImplementation(() => ({
      role: {
        findMany: jest.fn().mockResolvedValue([{ id: 'r1', name: 'admin', rank: 10 }]),
        upsert: jest.fn().mockResolvedValue({ id: 'r1', name: 'admin', rank: 10 }),
        delete: jest.fn().mockResolvedValue({}),
        findUnique: jest.fn().mockImplementation(({ where }) => Promise.resolve({ id: 'r1', name: where.name })),
      },
      permission: {
        findMany: jest.fn().mockResolvedValue([{ id: 'p1', name: 'read' }]),
        findUnique: jest.fn().mockResolvedValue({ id: 'p1', name: 'read' }),
      },
      rolePermission: { upsert: jest.fn(), delete: jest.fn(), findMany: jest.fn().mockResolvedValue([{ permission: { id: 'p1', name: 'read' } }]) },
    })),
  };
  return m;
});

describe('RoleService', () => {
  let s: RoleService;
  beforeEach(() => {
    s = new RoleService({ prisma: new PrismaClient() });
  });

  test('listRoles', async () => {
    const roles = await s.listRoles();
    expect(Array.isArray(roles)).toBe(true);
    expect(roles[0].name).toBe('admin');
  });

  test('upsertRole and delete', async () => {
    const r = await s.upsertRole('admin', 10, 'desc');
    expect(r.name).toBe('admin');
    await expect(s.deleteRole('admin')).resolves.toBeUndefined();
  });

  test('permissions flow', async () => {
    const perms = await s.listPermissions();
    expect(perms.length).toBeGreaterThan(0);
    await expect(s.grantPermissionToRole('admin', 'read')).resolves.toBeUndefined();
    await expect(s.revokePermissionFromRole('admin', 'read')).resolves.toBeUndefined();
    const rp = await s.listRolePermissions('admin');
    expect(Array.isArray(rp)).toBe(true);
  });
});
