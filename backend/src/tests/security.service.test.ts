import argon2 from 'argon2';
import * as totpLib from '../lib/totp';
import { PasswordChangeError, SecurityOperationError, SecurityService, type SecurityPrisma } from '../services/securityService';

jest.mock('argon2', () => {
  const hash = jest.fn();
  const verify = jest.fn();
  return {
    __esModule: true,
    default: { hash, verify, argon2id: 2 },
    argon2id: 2,
  };
});

jest.mock('../lib/totp', () => ({
  __esModule: true,
  buildTotpQrCode: jest.fn().mockResolvedValue('data:image/png;base64,qr'),
  buildTotpUri: jest.fn().mockReturnValue('otpauth://totp/mock'),
  generateTotpSecret: jest.fn().mockReturnValue('SECRET123456'),
  verifyTotpCode: jest.fn().mockReturnValue(true),
}));

const CURRENT_HASH = 'current-hash';
const OLD_PASSWORD = 'Old#Password1';
const NEW_PASSWORD = 'New#Password1!';
const AUTH_APP_LABEL = 'Authenticator app';
const GOOGLE_AUTH_LABEL = 'Google Authenticator';
const GOOGLE_AUTH_DESCRIPTION = 'Android + iOS code generator';
const AUTH_APP_HELPER = 'Use your authenticator app';
const GOOGLE_AUTH_DOCS = 'https://support.google.com/accounts/answer/1066447';
const DEFAULT_ISSUER = 'Pet Shelter Registry';
const OLD_SECRET = 'OLD-SECRET';
const PRIMARY_FACTOR_ID = 'factor-1';
const NEW_FACTOR_ID = 'factor-new';
const MFA_ENROLLED_AT = '2024-01-02T00:00:00Z';
const PENDING_TICKET = 'ticket-lock';
const PENDING_CONFLICT_MESSAGE = 'pending enrollment in progress';
const mockedTotp = totpLib as jest.Mocked<typeof totpLib>;

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
            label: AUTH_APP_LABEL,
            enabled: true,
            enrolledAt: MFA_ENROLLED_AT,
            lastUsedAt: '2024-01-20T00:00:00Z',
          }],
        },
      },
    },
    updatedAt: new Date('2024-01-05T00:00:00Z'),
  passwordHash: CURRENT_HASH,
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
      userMfaFactor: {
        count: jest.fn().mockResolvedValue(0),
        create: jest.fn().mockResolvedValue(null),
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn().mockResolvedValue([]),
        findUnique: jest.fn().mockResolvedValue(null),
        update: jest.fn().mockResolvedValue(null),
        delete: jest.fn().mockResolvedValue(null),
      },
      userBackupCode: {
        findMany: jest.fn().mockResolvedValue([]),
        deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
        createMany: jest.fn().mockResolvedValue({ count: 0 }),
      },
      userDevice: {
        findMany: jest.fn().mockResolvedValue([]),
        update: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue(null),
      },
      authenticatorCatalog: {
        findFirst: jest.fn().mockResolvedValue(null),
        findMany: jest.fn().mockResolvedValue([]),
      },
      $transaction: jest.fn(async (operations: Array<Promise<unknown>>) => Promise.all(operations)),
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

  it('includes pending enrollment metadata even when the factor row is missing', async () => {
    const pendingFactorId = 'pending-factor';
    const ticket = 'ticket-1234';
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    const pendingUser = {
      ...baseUser,
      metadata: {
        ...(baseUser.metadata || {}),
        security: {
          ...(baseUser.metadata?.security || {}),
          pendingTotp: {
            ticket,
            factorId: pendingFactorId,
            mode: 'rotate',
            expiresAt,
            label: GOOGLE_AUTH_LABEL,
            catalogId: 'google',
            type: 'totp',
            status: 'pending',
            catalog: {
              id: 'google',
              label: GOOGLE_AUTH_LABEL,
              description: GOOGLE_AUTH_DESCRIPTION,
              helper: AUTH_APP_HELPER,
              docsUrl: GOOGLE_AUTH_DOCS,
              tags: ['mobile'],
              issuer: DEFAULT_ISSUER,
            },
          },
        },
      },
    };
    const prisma = buildPrisma({
      user: { findUnique: jest.fn().mockResolvedValue(pendingUser) },
      userMfaFactor: { findMany: jest.fn().mockResolvedValue([]) },
    });
    const svc = new SecurityService({ prisma });
    const snapshot = await svc.getAccountSecuritySnapshot('user-1');
    expect(snapshot?.mfa.pendingEnrollment).toEqual(expect.objectContaining({
      ticket,
      factorId: pendingFactorId,
      mode: 'rotate',
      catalogId: 'google',
      label: GOOGLE_AUTH_LABEL,
      type: 'totp',
      status: 'pending',
    }));
    expect(snapshot?.mfa.pendingEnrollment?.expiresAt).toBe(expiresAt);
    expect(snapshot?.mfa.pendingEnrollment?.catalog).toEqual(expect.objectContaining({ id: 'google', label: GOOGLE_AUTH_LABEL }));
  expect(snapshot?.mfa.pendingEnrollment?.description).toBe(GOOGLE_AUTH_DESCRIPTION);
    expect(snapshot?.mfa.pendingEnrollment?.tags).toEqual(expect.arrayContaining(['mobile']));
  });

  it('deletes factors and clears pending enrollment metadata', async () => {
    const factor = {
      id: PRIMARY_FACTOR_ID,
      userId: 'user-1',
      type: 'TOTP',
      label: AUTH_APP_LABEL,
      secret: OLD_SECRET,
      enabled: true,
      status: 'ACTIVE',
      metadata: null,
      enrolledAt: new Date(MFA_ENROLLED_AT),
      lastUsedAt: null,
    };
    const pendingUser = {
      ...baseUser,
      metadata: {
        ...(baseUser.metadata || {}),
        security: {
          ...(baseUser.metadata?.security || {}),
          pendingTotp: {
            ticket: 'ticket-456',
            factorId: PRIMARY_FACTOR_ID,
            mode: 'create',
            expiresAt: new Date(Date.now() - 60_000).toISOString(),
          },
        },
      },
    };
    const deleteMany = jest.fn().mockResolvedValue({ count: 8 });
    const deleteFactor = jest.fn().mockResolvedValue(undefined);
    const updateUser = jest.fn().mockResolvedValue(pendingUser);
    const prisma = buildPrisma({
      userMfaFactor: {
        findFirst: jest.fn().mockResolvedValue(factor),
        delete: deleteFactor,
      },
      userBackupCode: { deleteMany },
      user: {
        findUnique: jest.fn().mockResolvedValue(pendingUser),
        update: updateUser,
      },
    });
    const svc = new SecurityService({ prisma });

    await svc.deleteMfaFactor('user-1', PRIMARY_FACTOR_ID);

    expect(deleteMany).toHaveBeenCalledWith({ where: { userId: 'user-1', factorId: PRIMARY_FACTOR_ID } });
    expect(deleteFactor).toHaveBeenCalledWith({ where: { id: PRIMARY_FACTOR_ID } });
    const updatedMetadata = updateUser.mock.calls[0]?.[0]?.data?.metadata;
    expect(updatedMetadata?.security?.pendingTotp).toBeUndefined();
  });

  it('strips enrollment metadata when enabling a factor', async () => {
    const factor = {
      id: PRIMARY_FACTOR_ID,
      userId: 'user-1',
      type: 'TOTP',
      label: AUTH_APP_LABEL,
      secret: OLD_SECRET,
      enabled: false,
      status: 'DISABLED',
      metadata: {
        enrollment: { rotating: true },
        notes: { rotatedAt: 'now' },
      },
    };
    const update = jest.fn().mockResolvedValue({ ...factor, enabled: true, status: 'ACTIVE', metadata: { notes: { rotatedAt: 'now' } } });
    const prisma = buildPrisma({
      userMfaFactor: {
        findFirst: jest.fn().mockResolvedValue(factor),
        update,
      },
    });
    const svc = new SecurityService({ prisma });

    await svc.enableMfaFactor('user-1', PRIMARY_FACTOR_ID);

    expect(update).toHaveBeenCalledWith({
      where: { id: PRIMARY_FACTOR_ID },
      data: expect.objectContaining({
        enabled: true,
        status: 'ACTIVE',
        metadata: expect.objectContaining({ notes: { rotatedAt: 'now' } }),
      }),
    });
    const metadataPayload = update.mock.calls[0]?.[0]?.data?.metadata;
    expect(metadataPayload?.enrollment).toBeUndefined();
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
        if (hash === CURRENT_HASH && value === OLD_PASSWORD) return Promise.resolve(true);
        return Promise.resolve(false);
      });
      mockedArgon2.hash.mockResolvedValue('new-hash');

      await svc.changePassword(
        'user-1',
        { currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD, signOutOthers: true },
        { currentRefreshToken: 'opaque-token', requestMeta: { ipAddress: '127.0.0.1', userAgent: 'jest' } },
      );

      expect(prisma.user.update).toHaveBeenCalledWith({ where: { id: 'user-1' }, data: { passwordHash: 'new-hash' } });
      expect(prisma.passwordHistory.create).toHaveBeenCalledWith({ data: { userId: 'user-1', passwordHash: CURRENT_HASH } });
      expect(prisma.refreshToken.updateMany).toHaveBeenCalledTimes(1);
      expect(prisma.auditLog.create).toHaveBeenCalledTimes(1);
    });

    it('rejects weak passwords', async () => {
      const prisma = buildPrisma();
      const svc = new SecurityService({ prisma });
      mockedArgon2.verify.mockImplementation((hash: string, value: string) => {
        if (hash === CURRENT_HASH && value === OLD_PASSWORD) return Promise.resolve(true);
        return Promise.resolve(false);
      });

      await expect(svc.changePassword('user-1', {
        currentPassword: OLD_PASSWORD,
        newPassword: 'weakpassword',
        signOutOthers: false,
      })).rejects.toBeInstanceOf(PasswordChangeError);
    });
  });

  describe('mfa management', () => {
    it('starts totp enrollment and persists pending metadata', async () => {
      const create = jest.fn().mockResolvedValue({
        id: NEW_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
        secret: 'SECRET123456',
        enabled: false,
        status: 'PENDING',
        metadata: null,
        enrolledAt: null,
        lastUsedAt: null,
      });
      const count = jest.fn().mockResolvedValue(1);
      const userUpdate = jest.fn().mockResolvedValue(baseUser);
      const prisma = buildPrisma({
        userMfaFactor: { create, count },
        user: { update: userUpdate },
      });
      const svc = new SecurityService({ prisma });
  const prompt = await svc.startTotpEnrollment('user-1', { label: AUTH_APP_LABEL });
  expect(prompt.factorId).toBe(NEW_FACTOR_ID);
      expect(prompt.mode).toBe('create');
      expect(create).toHaveBeenCalledTimes(1);
      const pending = userUpdate.mock.calls[0]?.[0]?.data?.metadata?.security?.pendingTotp;
      expect(pending).toBeTruthy();
  expect(pending.factorId).toBe(NEW_FACTOR_ID);
          expect(pending.label).toBe(AUTH_APP_LABEL);
          expect(pending.type).toBe('totp');
          expect(pending.status).toBe('pending');
    });

    it('associates catalog selections when provided during enrollment', async () => {
      const create = jest.fn().mockResolvedValue({
        id: NEW_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
        secret: 'SECRET123456',
        enabled: false,
        status: 'PENDING',
        metadata: null,
        enrolledAt: null,
        lastUsedAt: null,
        catalogId: 'google',
      });
      const prisma = buildPrisma({
        userMfaFactor: { create, count: jest.fn().mockResolvedValue(0) },
        authenticatorCatalog: {
          findFirst: jest.fn().mockResolvedValue({
            id: 'google',
            label: GOOGLE_AUTH_LABEL,
            description: GOOGLE_AUTH_DESCRIPTION,
            helper: AUTH_APP_HELPER,
            docsUrl: GOOGLE_AUTH_DOCS,
            issuer: DEFAULT_ISSUER,
            tags: ['mobile'],
            metadata: { platform: 'mobile' },
            factorType: 'totp',
            isArchived: false,
          }),
        },
      });
      const svc = new SecurityService({ prisma });
      const prompt = await svc.startTotpEnrollment('user-1', { catalogId: 'google' });
      expect(prisma.authenticatorCatalog.findFirst).toHaveBeenCalledWith(expect.objectContaining({
        where: expect.objectContaining({ id: 'google', isArchived: false }),
      }));
      expect(create).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ catalogId: 'google' }),
      }));
      expect(prompt.catalogId).toBe('google');
      const pending = (prisma.user.update as jest.Mock).mock.calls[0]?.[0]?.data?.metadata?.security?.pendingTotp;
  expect(pending.catalog).toEqual(expect.objectContaining({ id: 'google', description: GOOGLE_AUTH_DESCRIPTION }));
    });

    it('rejects unknown catalog identifiers', async () => {
      const prisma = buildPrisma({
        authenticatorCatalog: { findFirst: jest.fn().mockResolvedValue(null) },
      });
      const svc = new SecurityService({ prisma });
      await expect(svc.startTotpEnrollment('user-1', { catalogId: 'missing-id' })).rejects.toBeInstanceOf(SecurityOperationError);
    });


      it('rotates the existing factor when the requested label already exists', async () => {
        const existingFactor = {
          id: PRIMARY_FACTOR_ID,
          userId: 'user-1',
          type: 'TOTP',
          label: GOOGLE_AUTH_LABEL,
          secret: OLD_SECRET,
          enabled: true,
          status: 'ACTIVE',
          metadata: null,
    enrolledAt: new Date(MFA_ENROLLED_AT),
          lastUsedAt: null,
        };
        const prisma = buildPrisma({
          userMfaFactor: {
            findMany: jest.fn().mockResolvedValue([existingFactor]),
            findFirst: jest.fn().mockResolvedValue(existingFactor),
            update: jest.fn().mockResolvedValue(existingFactor),
            create: jest.fn(),
          },
          user: {
            findUnique: jest.fn().mockResolvedValue(baseUser),
            update: jest.fn().mockResolvedValue(baseUser),
          },
        });
        const svc = new SecurityService({ prisma });
  const prompt = await svc.startTotpEnrollment('user-1', { label: GOOGLE_AUTH_LABEL });
        expect(prompt.mode).toBe('rotate');
        expect(prisma.userMfaFactor.create).not.toHaveBeenCalled();
        expect(prisma.userMfaFactor.update).toHaveBeenCalled();
      });

    it('regenerates an existing totp factor and schedules rotation', async () => {
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
  label: AUTH_APP_LABEL,
  secret: OLD_SECRET,
        enabled: true,
        status: 'ACTIVE',
        metadata: null,
  enrolledAt: new Date(MFA_ENROLLED_AT),
        lastUsedAt: null,
      };
      const userRecord = { ...baseUser };
      const prisma = buildPrisma({
        user: {
          findUnique: jest.fn().mockResolvedValue(userRecord),
          update: jest.fn().mockResolvedValue(userRecord),
        },
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          update: jest.fn().mockResolvedValue(factor),
        },
      });
      const svc = new SecurityService({ prisma });
  const prompt = await svc.regenerateTotpFactor('user-1', PRIMARY_FACTOR_ID, { accountName: 'custom@example.com' });
      expect(prompt.mode).toBe('rotate');
  expect(prompt.factorId).toBe(PRIMARY_FACTOR_ID);
      const pending = (prisma.user.update as jest.Mock).mock.calls[0]?.[0]?.data?.metadata?.security?.pendingTotp;
      expect(pending).toBeTruthy();
      expect(pending.mode).toBe('rotate');
      expect(pending.label).toBe(AUTH_APP_LABEL);
    });

    it('updates catalog association when rotating with a new selection', async () => {
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
  secret: OLD_SECRET,
        enabled: true,
        status: 'ACTIVE',
        metadata: null,
        enrolledAt: new Date(MFA_ENROLLED_AT),
        lastUsedAt: null,
        catalogId: null,
      };
      const prisma = buildPrisma({
        user: {
          findUnique: jest.fn().mockResolvedValue(baseUser),
          update: jest.fn().mockResolvedValue(baseUser),
        },
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          update: jest.fn().mockResolvedValue({ ...factor, catalogId: 'google' }),
        },
        authenticatorCatalog: {
          findFirst: jest.fn().mockResolvedValue({
            id: 'google',
            label: GOOGLE_AUTH_LABEL,
            description: GOOGLE_AUTH_DESCRIPTION,
            helper: AUTH_APP_HELPER,
            docsUrl: GOOGLE_AUTH_DOCS,
            issuer: DEFAULT_ISSUER,
            tags: ['mobile'],
            metadata: { platform: 'mobile' },
            factorType: 'totp',
            isArchived: false,
          }),
        },
      });
      const svc = new SecurityService({ prisma });
      const prompt = await svc.regenerateTotpFactor('user-1', factor.id, { catalogId: 'google' });
      expect(prisma.userMfaFactor.update).toHaveBeenCalledWith(expect.objectContaining({
        data: expect.objectContaining({ catalogId: 'google' }),
      }));
      expect(prompt.catalogId).toBe('google');
      const pending = (prisma.user.update as jest.Mock).mock.calls[0]?.[0]?.data?.metadata?.security?.pendingTotp;
      expect(pending.catalogId).toBe('google');
      expect(pending.catalog).toEqual(expect.objectContaining({ id: 'google', label: GOOGLE_AUTH_LABEL }));
    });


    it('confirms pending totp enrollment and refreshes backup codes', async () => {
      const ticket = 'ticket-123';
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const pendingUser = {
        ...baseUser,
        metadata: {
          ...(baseUser.metadata || {}),
          security: {
            ...(baseUser.metadata?.security || {}),
            pendingTotp: {
              ticket,
              factorId: PRIMARY_FACTOR_ID,
              mode: 'create',
              expiresAt,
            },
          },
        },
      };
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
  label: AUTH_APP_LABEL,
        secret: 'SECRET123456',
        enabled: false,
        status: 'PENDING',
        metadata: null,
        enrolledAt: null,
        lastUsedAt: null,
      };
      const prisma = buildPrisma({
        user: {
          findUnique: jest.fn().mockResolvedValue(pendingUser),
          update: jest.fn().mockResolvedValue(pendingUser),
        },
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          update: jest.fn().mockResolvedValue(factor),
          findUnique: jest.fn().mockResolvedValue({ ...factor, enabled: true, status: 'ACTIVE' }),
        },
        userBackupCode: {
          deleteMany: jest.fn().mockResolvedValue({ count: 0 }),
          createMany: jest.fn().mockResolvedValue({ count: 8 }),
        },
        $transaction: jest.fn(async (operations: Array<Promise<unknown>>) => Promise.all(operations)),
  });
  const svc = new SecurityService({ prisma });
      let codeIndex = 0;
  (svc as unknown as { createBackupCode: jest.Mock }).createBackupCode = jest.fn(() => `CODE-${++codeIndex}`);
      mockedTotp.verifyTotpCode.mockReturnValueOnce(true);
  const result = await svc.confirmTotpEnrollment('user-1', { ticket, code: '123456' });
  expect(result.factor.id).toBe(PRIMARY_FACTOR_ID);
      expect(result.backupCodes).toHaveLength(8);
      expect(prisma.userBackupCode.deleteMany).toHaveBeenCalledTimes(1);
      expect(prisma.userBackupCode.createMany).toHaveBeenCalledTimes(1);
      const pending = (prisma.user.update as jest.Mock).mock.calls.pop()?.[0]?.data?.metadata?.security?.pendingTotp;
      expect(pending).toBeUndefined();
      expect(mockedTotp.verifyTotpCode).toHaveBeenCalledWith('SECRET123456', '123456');
    });

    it('enables a disabled factor', async () => {
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
        secret: 'SECRET123456',
        enabled: false,
        status: 'DISABLED',
        metadata: { enrollment: { rotating: false } },
      };
      const prisma = buildPrisma({
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          update: jest.fn().mockResolvedValue({ ...factor, enabled: true, status: 'ACTIVE' }),
        },
      });
      const svc = new SecurityService({ prisma });

      await svc.enableMfaFactor('user-1', PRIMARY_FACTOR_ID);

      expect(prisma.userMfaFactor.update).toHaveBeenCalledWith({
        where: { id: PRIMARY_FACTOR_ID },
        data: expect.objectContaining({ enabled: true, status: 'ACTIVE' }),
      });
    });

    it('clears matching pending enrollment metadata before enabling', async () => {
      const expiresAt = new Date(Date.now() + 90_000).toISOString();
      const pendingUser = {
        ...baseUser,
        metadata: {
          ...(baseUser.metadata || {}),
          security: {
            ...(baseUser.metadata?.security || {}),
            pendingTotp: {
              ticket: PENDING_TICKET,
              factorId: PRIMARY_FACTOR_ID,
              mode: 'rotate',
              expiresAt,
              type: 'totp',
              label: AUTH_APP_LABEL,
            },
          },
        },
      };
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
        secret: 'SECRET123456',
        enabled: false,
        status: 'DISABLED',
        metadata: { enrollment: { rotating: true } },
      };
      const prisma = buildPrisma({
        user: {
          findUnique: jest.fn().mockResolvedValue(pendingUser),
          update: jest.fn().mockResolvedValue(pendingUser),
        },
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          update: jest.fn().mockResolvedValue({ ...factor, enabled: true, status: 'ACTIVE' }),
        },
      });
      const svc = new SecurityService({ prisma });

      await svc.enableMfaFactor('user-1', PRIMARY_FACTOR_ID);

      const metadata = (prisma.user.update as jest.Mock).mock.calls[0]?.[0]?.data?.metadata;
      expect(metadata?.security?.pendingTotp).toBeUndefined();
      expect(prisma.userMfaFactor.update).toHaveBeenCalledWith({
        where: { id: PRIMARY_FACTOR_ID },
        data: expect.objectContaining({ enabled: true, status: 'ACTIVE' }),
      });
    });

    it('rejects enabling revoked factors', async () => {
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
        secret: 'SECRET123456',
        enabled: false,
        status: 'REVOKED',
        metadata: null,
      };
      const prisma = buildPrisma({
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          update: jest.fn(),
        },
      });
      const svc = new SecurityService({ prisma });

      await expect(svc.enableMfaFactor('user-1', PRIMARY_FACTOR_ID)).rejects.toThrow('factor revoked');
      expect(prisma.userMfaFactor.update).not.toHaveBeenCalled();
    });

    it('prevents disabling a factor while its rotation is pending', async () => {
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
        secret: OLD_SECRET,
        enabled: true,
        status: 'ACTIVE',
        metadata: null,
      };
      const pendingUser = {
        ...baseUser,
        metadata: {
          ...(baseUser.metadata || {}),
          security: {
            ...(baseUser.metadata?.security || {}),
            pendingTotp: {
              ticket: PENDING_TICKET,
              factorId: PRIMARY_FACTOR_ID,
              mode: 'rotate',
              expiresAt: new Date(Date.now() + 90_000).toISOString(),
              type: 'totp',
              label: AUTH_APP_LABEL,
            },
          },
        },
      };
      const prisma = buildPrisma({
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          update: jest.fn(),
        },
        user: {
          findUnique: jest.fn().mockResolvedValue(pendingUser),
          update: jest.fn(),
        },
      });
      const svc = new SecurityService({ prisma });

      await expect(svc.disableMfaFactor('user-1', PRIMARY_FACTOR_ID)).rejects.toMatchObject({
        status: 409,
        message: PENDING_CONFLICT_MESSAGE,
      });
      expect(prisma.userMfaFactor.update).not.toHaveBeenCalled();
    });

    it('prevents deleting a factor while its enrollment is pending', async () => {
      const factor = {
        id: PRIMARY_FACTOR_ID,
        userId: 'user-1',
        type: 'TOTP',
        label: AUTH_APP_LABEL,
        secret: OLD_SECRET,
        enabled: true,
        status: 'ACTIVE',
        metadata: null,
      };
      const pendingUser = {
        ...baseUser,
        metadata: {
          ...(baseUser.metadata || {}),
          security: {
            ...(baseUser.metadata?.security || {}),
            pendingTotp: {
              ticket: PENDING_TICKET,
              factorId: PRIMARY_FACTOR_ID,
              mode: 'create',
              expiresAt: new Date(Date.now() + 45_000).toISOString(),
              type: 'totp',
              label: AUTH_APP_LABEL,
            },
          },
        },
      };
      const deleteMock = jest.fn();
      const prisma = buildPrisma({
        userMfaFactor: {
          findFirst: jest.fn().mockResolvedValue(factor),
          delete: deleteMock,
        },
        user: {
          findUnique: jest.fn().mockResolvedValue(pendingUser),
          update: jest.fn(),
        },
      });
      const svc = new SecurityService({ prisma });

      await expect(svc.deleteMfaFactor('user-1', PRIMARY_FACTOR_ID)).rejects.toMatchObject({
        status: 409,
        message: PENDING_CONFLICT_MESSAGE,
      });
      expect(deleteMock).not.toHaveBeenCalled();
    });

    it('lists authenticator catalog entries from prisma when available', async () => {
      const prisma = buildPrisma({
        authenticatorCatalog: {
          findMany: jest.fn().mockResolvedValue([
            {
              id: 'custom-app',
              label: 'Custom App',
              description: 'Custom authenticator',
              helper: 'Use the custom mobile app',
              docsUrl: 'https://example.com/app',
              issuer: 'Custom Issuer',
              tags: ['mobile'],
              metadata: { region: 'us' },
              factorType: 'TOTP',
              sortOrder: 5,
              isArchived: false,
            },
          ]),
          findFirst: jest.fn().mockResolvedValue(null),
        },
      });
      const svc = new SecurityService({ prisma });
      const result = await svc.listAuthenticatorCatalog();
      expect(prisma.authenticatorCatalog.findMany).toHaveBeenCalledWith(expect.objectContaining({
        where: { isArchived: false },
      }));
      expect(result).toEqual([
        expect.objectContaining({ id: 'custom-app', label: 'Custom App', factorType: 'TOTP', sortOrder: 5 }),
      ]);
    });

    it('falls back to default catalog seeds when no rows exist', async () => {
      const prisma = buildPrisma({
        authenticatorCatalog: {
          findMany: jest.fn().mockResolvedValue([]),
          findFirst: jest.fn().mockResolvedValue(null),
        },
      });
      const svc = new SecurityService({ prisma });
      const result = await svc.listAuthenticatorCatalog({ factorType: 'totp' });
      expect(result.length).toBeGreaterThan(0);
      expect(result.every(entry => entry.factorType === 'TOTP')).toBe(true);
    });
  });
});

