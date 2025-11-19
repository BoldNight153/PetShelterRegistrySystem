import argon2 from 'argon2';
import { PasswordChangeError, SecurityService, type SecurityPrisma } from '../services/securityService';

jest.mock('argon2', () => {
  const hash = jest.fn();
  const verify = jest.fn();
  return {
    __esModule: true,
    default: { hash, verify, argon2id: 2 },
    argon2id: 2,
  };
});

describe('SecurityService', () => {
  const baseUser = {
    id: 'user-1',
    email: 'user@example.com',
    emailVerified: new Date('2024-01-01T00:00:00Z'),
    metadata: {
      security: {
        recovery: {
          backupCodesRemaining: 5,
          primaryEmail: { type: 'email', value: 'user@example.com', verified: true },
        },
        alerts: {
          preferences: [{ event: 'login', label: 'Login', enabled: true, channels: ['email'] }],
          defaultChannels: ['email'],
        },
        mfa: {
          factors: [{
            id: 'totp-1',
            type: 'totp',
            label: 'Authenticator app',
            enabled: true,
            enrolledAt: '2024-01-02T00:00:00Z',
            lastUsedAt: '2024-01-20T00:00:00Z',
          }],
        },
      },
    },
    updatedAt: new Date('2024-01-05T00:00:00Z'),
    passwordHash: 'current-hash',
  } as any;

  const refreshToken = {
    id: 'rt-1',
    userId: 'user-1',
    token: 'opaque-token',
    expiresAt: new Date('2024-02-01T00:00:00Z'),
    revokedAt: null,
    replacedByToken: null,
    userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36',
    ipAddress: '192.168.1.10',
    createdAt: new Date('2024-01-10T00:00:00Z'),
  };

  type PrismaOverrides = Partial<{ [K in keyof SecurityPrisma]: Partial<SecurityPrisma[K]> }>;

  function buildPrisma(overrides?: PrismaOverrides): SecurityPrisma {
    const base = basePrismaFactory();
    if (!overrides) return base;
    (Object.keys(overrides) as (keyof SecurityPrisma)[]).forEach(key => {
      const fragment = overrides[key];
      if (!fragment) return;
      Object.assign(base[key] as Record<string, any>, fragment);
    });
    return base;
  }

  function basePrismaFactory(): SecurityPrisma {
    return {
      user: {
        findUnique: jest.fn().mockResolvedValue(baseUser),
        update: jest.fn().mockResolvedValue(baseUser),
      },
      passwordHistory: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'ph-1', userId: 'user-1', passwordHash: 'hash', createdAt: new Date('2024-01-03T00:00:00Z') },
          { id: 'ph-2', userId: 'user-1', passwordHash: 'older', createdAt: new Date('2023-10-01T00:00:00Z') },
        ]),
        create: jest.fn().mockResolvedValue(undefined),
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
      refreshToken: {
        findMany: jest.fn().mockResolvedValue([refreshToken]),
        updateMany: jest.fn().mockResolvedValue({ count: 1 }),
      },
      auditLog: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'audit-1', userId: 'user-1', action: 'auth.login.success', createdAt: new Date('2024-01-15T00:00:00Z'), ipAddress: '192.168.1.10', metadata: null },
        ]),
        create: jest.fn().mockResolvedValue(undefined),
      },
      setting: {
        findMany: jest.fn().mockResolvedValue([
          { id: 's1', category: 'security', key: 'passwordMinLength', value: 14, updatedAt: new Date(), updatedBy: null },
          { id: 's2', category: 'security', key: 'passwordHistoryLimit', value: 5, updatedAt: new Date(), updatedBy: null },
        ]),
      },
    } as unknown as SecurityPrisma;
  }

  const mockedArgon2 = argon2 as unknown as { hash: jest.Mock; verify: jest.Mock; argon2id: number };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('builds a snapshot with derived overview data', async () => {
    const prisma = buildPrisma();
  const svc = new SecurityService({ prisma });
    const snapshot = await svc.getAccountSecuritySnapshot('user-1');
    expect(snapshot).not.toBeNull();
    expect(snapshot?.overview.mfaEnabled).toBe(true);
    expect(snapshot?.password.policy.minLength).toBe(14);
    expect(snapshot?.sessions.summary.activeCount).toBe(1);
    expect(snapshot?.events).toHaveLength(1);
  });

  it('returns session summary even when no tokens exist', async () => {
    const prisma = buildPrisma({ refreshToken: { findMany: jest.fn().mockResolvedValue([]) } });
  const svc = new SecurityService({ prisma });
    const sessions = await svc.listSessions('user-1');
    expect(sessions.summary.activeCount).toBe(0);
    expect(Array.isArray(sessions.list)).toBe(true);
  });

  it('returns null snapshot when user is missing', async () => {
    const prisma = buildPrisma({ user: { findUnique: jest.fn().mockResolvedValue(null) } });
    const svc = new SecurityService({ prisma });
    const snapshot = await svc.getAccountSecuritySnapshot('missing');
    expect(snapshot).toBeNull();
  });

  it('updates recovery settings and persists metadata', async () => {
    const update = jest.fn().mockResolvedValue(baseUser);
    const prisma = buildPrisma({ user: { update } });
    const svc = new SecurityService({ prisma });
    const result = await svc.updateRecoverySettings('user-1', {
      primaryEmail: { type: 'email', value: 'security@example.com', verified: true, lastVerifiedAt: '2024-01-01T00:00:00Z' },
      backupEmail: { type: 'email', value: 'backup@example.com', verified: false },
      sms: { type: 'sms', value: '+15550001111', verified: false },
      backupCodesRemaining: 7,
      contacts: [{ id: 'contact-1', name: 'Ops', email: 'ops@example.com', phone: null, verified: true }],
      lastCodesGeneratedAt: '2024-01-15T00:00:00Z',
    });
    expect(result).not.toBeNull();
    expect(result?.primaryEmail.value).toBe('security@example.com');
    expect(update).toHaveBeenCalledTimes(1);
    const payload = update.mock.calls[0]?.[0]?.data?.metadata;
    expect(payload).toBeDefined();
  });

  it('returns null when updating recovery for unknown user', async () => {
    const prisma = buildPrisma({ user: { findUnique: jest.fn().mockResolvedValue(null) } });
    const svc = new SecurityService({ prisma });
    const result = await svc.updateRecoverySettings('missing', {
      primaryEmail: { type: 'email', value: 'missing@example.com', verified: false },
      contacts: [],
      backupCodesRemaining: 0,
    });
    expect(result).toBeNull();
  });

  it('updates alert preferences and persists metadata', async () => {
    const update = jest.fn().mockResolvedValue(baseUser);
    const prisma = buildPrisma({ user: { update } });
    const svc = new SecurityService({ prisma });
    const result = await svc.updateAlertSettings('user-1', {
      preferences: [
        { event: 'login', label: 'Login alerts', enabled: true, channels: ['email', 'push'] },
        { event: 'new_device', label: 'New device', enabled: false, channels: ['email'] },
      ],
      defaultChannels: ['email', 'sms'],
    });
    expect(result).not.toBeNull();
    expect(result?.defaultChannels).toEqual(expect.arrayContaining(['sms']));
    expect(result?.preferences).toHaveLength(2);
    expect(update).toHaveBeenCalledTimes(1);
  });

  describe('changePassword', () => {
    it('updates password, records history, and revokes other sessions', async () => {
      const prisma = buildPrisma();
      const svc = new SecurityService({ prisma });
      mockedArgon2.verify.mockImplementation((hash: string, value: string) => {
        if (hash === 'current-hash' && value === 'Old#Password1') return Promise.resolve(true);
        return Promise.resolve(false);
      });
      mockedArgon2.hash.mockResolvedValue('new-hash');

      await svc.changePassword(
        'user-1',
        { currentPassword: 'Old#Password1', newPassword: 'New#Password1!', signOutOthers: true },
        { currentRefreshToken: 'opaque-token', requestMeta: { ipAddress: '127.0.0.1', userAgent: 'jest' } },
      );

      expect(prisma.user.update).toHaveBeenCalledWith({ where: { id: 'user-1' }, data: { passwordHash: 'new-hash' } });
      expect(prisma.passwordHistory.create).toHaveBeenCalledWith({ data: { userId: 'user-1', passwordHash: 'current-hash' } });
      expect(prisma.refreshToken.updateMany).toHaveBeenCalledTimes(1);
      expect(prisma.auditLog.create).toHaveBeenCalledTimes(1);
    });

    it('rejects weak passwords', async () => {
      const prisma = buildPrisma();
      const svc = new SecurityService({ prisma });
      mockedArgon2.verify.mockImplementation((hash: string, value: string) => {
        if (hash === 'current-hash' && value === 'Old#Password1') return Promise.resolve(true);
        return Promise.resolve(false);
      });

      await expect(svc.changePassword('user-1', {
        currentPassword: 'Old#Password1',
        newPassword: 'weakpassword',
        signOutOthers: false,
      })).rejects.toBeInstanceOf(PasswordChangeError);
    });
  });
});
