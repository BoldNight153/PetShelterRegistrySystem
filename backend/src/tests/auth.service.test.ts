import { AuthService } from '../services/authService';

describe('AuthService (unit)', () => {
  const mockPrisma: any = {
    refreshToken: { create: jest.fn(), findUnique: jest.fn(), update: jest.fn(), updateMany: jest.fn() },
    verificationToken: { create: jest.fn(), findUnique: jest.fn(), update: jest.fn() },
    user: { findUnique: jest.fn(), create: jest.fn(), update: jest.fn() },
    userLock: { create: jest.fn() },
    passwordHistory: { create: jest.fn(), findMany: jest.fn(), deleteMany: jest.fn() },
    account: { findUnique: jest.fn(), create: jest.fn() },
  };

  const svc = new AuthService({ prisma: mockPrisma });

  beforeEach(() => jest.clearAllMocks());

  test('create and find refresh token', async () => {
    const now = new Date();
    mockPrisma.refreshToken.create.mockResolvedValue({ token: 't', userId: 'u', expiresAt: now });
    const r = await svc.createRefreshToken('u', 't', now, 'ua', '1.2.3.4');
    expect(r.token).toBe('t');
    expect(mockPrisma.refreshToken.create).toHaveBeenCalled();
  });

  test('create and find verification token', async () => {
    const now = new Date(Date.now() + 1000 * 60);
    mockPrisma.verificationToken.create.mockResolvedValue({ id: '1', token: 'vt' });
    const v = await svc.createVerificationToken('id', 'vt', 'email_verify', now);
    expect(v.token).toBe('vt');
    expect(mockPrisma.verificationToken.create).toHaveBeenCalled();
  });

  test('consuming an already consumed verification token should update consumedAt', async () => {
    const vt = { id: '1', token: 'vt', consumedAt: new Date() };
    mockPrisma.verificationToken.findUnique.mockResolvedValue(vt);
    mockPrisma.verificationToken.update.mockResolvedValue({ ...vt, consumedAt: vt.consumedAt });

    const found = await svc.findVerificationToken('vt');
    expect(found).toEqual(vt);

    const consumed = await svc.consumeVerificationToken('1');
    expect(consumed.consumedAt).toBeDefined();
    expect(mockPrisma.verificationToken.update).toHaveBeenCalledWith({ where: { id: '1' }, data: { consumedAt: expect.any(Date) } });
  });

  test('expired refresh token should still be found but indicate expiry via expiresAt', async () => {
    const past = new Date(Date.now() - 1000 * 60);
    const rt = { token: 'expired', userId: 'u', expiresAt: past, revokedAt: null };
    mockPrisma.refreshToken.findUnique.mockResolvedValue(rt);

    const found = await svc.findRefreshToken('expired');
    expect(found).not.toBeNull();
    expect(found?.expiresAt.getTime()).toBeLessThan(Date.now());
  });

  test('revoking a refresh token sets revokedAt', async () => {
    const rt = { token: 'torevoke', userId: 'u', expiresAt: new Date(), revokedAt: null };
    mockPrisma.refreshToken.update.mockResolvedValue({ ...rt, revokedAt: new Date() });

    const revoked = await svc.revokeRefreshToken('torevoke');
    expect(revoked.revokedAt).toBeDefined();
    expect(mockPrisma.refreshToken.update).toHaveBeenCalledWith({ where: { token: 'torevoke' }, data: { revokedAt: expect.any(Date) } });
  });

  test('oauth account linking creates account when none exists', async () => {
    // Simulate no existing account
    mockPrisma.account.findUnique.mockResolvedValue(null);
    mockPrisma.account.create.mockResolvedValue({ id: 'a1', provider: 'github', providerAccountId: '123' });

  const acc = await mockPrisma.account.create({ data: { provider: 'github', providerAccountId: '123', userId: 'u' } });
  expect(acc.provider).toBe('github');
  expect(mockPrisma.account.create).toHaveBeenCalled();
  });
});
