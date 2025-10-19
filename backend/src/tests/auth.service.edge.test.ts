import { AuthService } from '../services/authService';

// Minimal mock Prisma implementation sufficient for AuthService methods used
function createMockPrisma() {
  const verificationTokens: any[] = [];
  const refreshTokens: any[] = [];
  return {
    verificationToken: {
      create: jest.fn(async ({ data }) => {
        const row = { id: (verificationTokens.length + 1).toString(), ...data, createdAt: new Date() };
        verificationTokens.push(row);
        return row;
      }),
      findUnique: jest.fn(async ({ where: { token } }) => verificationTokens.find(v => v.token === token) || null),
      update: jest.fn(async ({ where: { id }, data }) => {
        const idx = verificationTokens.findIndex(v => v.id === id);
        if (idx === -1) throw new Error('not found');
        verificationTokens[idx] = { ...verificationTokens[idx], ...data };
        return verificationTokens[idx];
      }),
    },
    refreshToken: {
      create: jest.fn(async ({ data }) => {
        const row = { id: (refreshTokens.length + 1).toString(), ...data, createdAt: new Date() };
        refreshTokens.push(row);
        return row;
      }),
      findUnique: jest.fn(async ({ where: { token } }) => refreshTokens.find(r => r.token === token) || null),
      update: jest.fn(async ({ where: { token }, data }) => {
        const idx = refreshTokens.findIndex(r => r.token === token);
        if (idx === -1) throw new Error('not found');
        refreshTokens[idx] = { ...refreshTokens[idx], ...data };
        return refreshTokens[idx];
      }),
      updateMany: jest.fn(async ({ where: { userId, revokedAt }, data }) => {
        const matched = refreshTokens.filter(r => r.userId === userId && r.revokedAt === revokedAt).length;
        refreshTokens.forEach(r => {
          if (r.userId === userId && r.revokedAt === revokedAt) r.revokedAt = data.revokedAt;
        });
        return { count: matched };
      }),
    },
    user: {
      findUnique: jest.fn(async ({ where: { email } }) => null),
      create: jest.fn(async ({ data }) => ({ id: 'u1', ...data })),
      update: jest.fn(async ({ where: { id }, data }) => ({ id, ...data })),
    },
  };
}

describe('AuthService edge cases', () => {
  test('consumeVerificationToken sets consumedAt', async () => {
    const mockPrisma = createMockPrisma() as any;
    const svc = new AuthService({ prisma: mockPrisma });

    const token = svc.generateToken();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    const created = await svc.createVerificationToken('user@example.com', token, 'email_verify', expiresAt);
    expect(created.token).toBe(token);

    const found = await svc.findVerificationToken(token);
    expect(found).not.toBeNull();

    const consumed = await svc.consumeVerificationToken(found!.id);
    expect(consumed.consumedAt).toBeDefined();
  });

  test('revokeRefreshToken updates revokedAt and revokeAll updates multiple', async () => {
    const mockPrisma = createMockPrisma() as any;
    const svc = new AuthService({ prisma: mockPrisma });

    const rt = await svc.createRefreshToken('u1', 'r1', new Date(Date.now() + 1000 * 60 * 60));
    expect(rt.token).toBe('r1');

    const updated = await svc.revokeRefreshToken('r1');
    expect(updated.revokedAt).toBeDefined();

    // create two more tokens and test revokeAll
    await svc.createRefreshToken('u2', 'r2', new Date(Date.now() + 1000 * 60 * 60));
    await svc.createRefreshToken('u2', 'r3', new Date(Date.now() + 1000 * 60 * 60));

    const res = await svc.revokeAllRefreshTokens('u2');
    expect(mockPrisma.refreshToken.updateMany).toHaveBeenCalled();
  });
});
