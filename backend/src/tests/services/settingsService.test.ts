import { SettingsService } from '../../services/settingsService';

describe('SettingsService', () => {

  afterEach(() => {
    jest.resetAllMocks();
  });

  it('normalizes audit and auth settings when listing', async () => {
    const allowedEntries = [
      { id: 'google' },
      { id: 'microsoft' },
      { id: 'webauthn_keys' },
      { id: 'backup_codes' },
    ];
    const prisma = {
      setting: {
        findMany: jest.fn().mockResolvedValue([
          { category: 'auth', key: 'mode', value: 'jwt' },
          { category: 'auth', key: 'google', value: 'false' },
          { category: 'auth', key: 'authenticators', value: ['invalid'] },
          { category: 'audit', key: 'alerts', value: { channels: { email: false } } },
        ]),
        upsert: jest.fn(),
      },
      authenticatorCatalog: {
        findMany: jest.fn().mockResolvedValue(allowedEntries),
      },
      $transaction: jest.fn().mockImplementation(async (operations: Array<Promise<unknown>>) => Promise.all(operations)),
    };
    const service = new SettingsService({ prisma: prisma as any });
    const result = await service.listSettings();
    expect(result.auth.mode).toBe('jwt');
    expect(result.auth.google).toBe(false);
    expect(result.auth.authenticators).toEqual(allowedEntries.map(entry => entry.id));
    expect(result.audit.alerts.channels.email).toBe(false);
    expect(result.audit.alerts.channels.slack).toBe(true);
  });

  it('preserves unknown authenticator ids when requested', async () => {
    const prisma = {
      setting: {
        findMany: jest.fn().mockResolvedValue([
          { category: 'auth', key: 'authenticators', value: ['google', 'phantom-id'] },
        ]),
      },
      authenticatorCatalog: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'google', isArchived: false },
          { id: 'microsoft', isArchived: false },
        ]),
      },
    };
    const service = new SettingsService({ prisma: prisma as any });
    const result = await service.listSettings('auth', { preserveUnknownAuth: true });
    expect(result.auth.authenticators).toEqual(['google', 'phantom-id']);
    expect(prisma.authenticatorCatalog.findMany).toHaveBeenCalledTimes(1);
  });

  it('falls back to allowed authenticators when all catalog entries are archived', async () => {
    const prisma = {
      setting: {
        findMany: jest.fn().mockResolvedValue([
          { category: 'auth', key: 'authenticators', value: [] },
        ]),
      },
      authenticatorCatalog: {
        findMany: jest.fn().mockResolvedValue([
          { id: 'legacy_one', isArchived: true },
          { id: 'legacy_two', isArchived: true },
        ]),
      },
    };
    const service = new SettingsService({ prisma: prisma as any });
    const result = await service.listSettings('auth');
    expect(result.auth.authenticators).toEqual(['legacy_one', 'legacy_two']);
  });

  it('sanitizes auth entries before writing to the database', async () => {
    const allowedEntries = [
      { id: 'google' },
      { id: 'push_trusted' },
      { id: 'backup_codes' },
    ];
    const prisma = {
      setting: {
        findMany: jest.fn().mockResolvedValue([]),
        upsert: jest.fn(),
      },
      authenticatorCatalog: {
        findMany: jest.fn().mockResolvedValue(allowedEntries),
      },
      $transaction: jest.fn().mockImplementation(async (operations: Array<Promise<unknown>>) => Promise.all(operations)),
    };
    const service = new SettingsService({ prisma: prisma as any });
    await service.upsertSettings('auth', [
      { key: 'google', value: 'false' },
      { key: 'github', value: 'true' },
      { key: 'authenticators', value: ['google', 'invalid', 'backup_codes'] },
    ], 'actor-123');

    const upsertCalls = prisma.setting.upsert.mock.calls as Array<[any]>;
    const googleCall = upsertCalls.find(([args]) => args.where.category_key.key === 'google');
    expect(googleCall?.[0].create.value).toBe(false);
    const authenticatorCall = upsertCalls.find(([args]) => args.where.category_key.key === 'authenticators');
    expect(authenticatorCall?.[0].create.value).toEqual(['google', 'backup_codes']);
    for (const [args] of upsertCalls) {
      expect(args.create.updatedBy).toBe('actor-123');
      expect(args.update.updatedBy).toBe('actor-123');
    }
    expect(prisma.$transaction).toHaveBeenCalledTimes(1);
  });
});
