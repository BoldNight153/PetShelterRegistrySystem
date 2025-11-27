import { NotificationService, createDefaultNotificationSettings, type NotificationPrisma } from '../services/notificationService';

function buildUser(overrides: Record<string, any> = {}) {
  return {
    id: 'user-1',
    email: 'ops@example.com',
    metadata: overrides.metadata ?? null,
    ...overrides,
  } as any;
}

type DeviceOverrides = {
  findMany?: jest.Mock;
  findFirst?: jest.Mock;
  create?: jest.Mock;
  update?: jest.Mock;
  updateMany?: jest.Mock;
};

function buildPrisma(
  userRecord: any,
  overrides?: { findUnique?: jest.Mock; update?: jest.Mock; devices?: DeviceOverrides },
): NotificationPrisma {
  const findUnique = overrides?.findUnique ?? jest.fn().mockImplementation(async (args: { where: { id: string } }) => {
    if (!userRecord || args.where.id !== userRecord.id) return null;
    return userRecord;
  });
  const update = overrides?.update ?? jest.fn().mockResolvedValue(userRecord);
  const devices = overrides?.devices ?? {};
  return {
    user: {
      findUnique,
      update,
    },
    notificationDeviceRegistration: {
      findMany: devices.findMany ?? jest.fn().mockResolvedValue([]),
      findFirst: devices.findFirst ?? jest.fn().mockResolvedValue(null),
      create: devices.create ?? jest.fn().mockResolvedValue({ id: 'device-1' }),
      update: devices.update ?? jest.fn().mockResolvedValue({ id: 'device-1' }),
      updateMany: devices.updateMany ?? jest.fn().mockResolvedValue({ count: 1 }),
    },
  } as unknown as NotificationPrisma;
}

describe('NotificationService', () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it('returns defaults when metadata is missing', async () => {
    const user = buildUser({ metadata: null });
    const prisma = buildPrisma(user);
    const svc = new NotificationService({ prisma });

    const settings = await svc.getNotificationSettings('user-1');

    expect(settings).toEqual(createDefaultNotificationSettings());
    expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { id: 'user-1' }, include: { notificationDevices: true } });
  });

  it('builds topics from legacy security alerts when notifications are absent', async () => {
    const user = buildUser({
      metadata: {
        security: {
          alerts: {
            preferences: [
              { event: 'security_login', label: 'Legacy login alert', enabled: true, channels: ['email', 'sms'] },
            ],
            defaultChannels: ['email', 'sms'],
          },
        },
      },
    });
    const prisma = buildPrisma(user);
    const svc = new NotificationService({ prisma });

    const settings = await svc.getNotificationSettings('user-1');

    expect(settings).not.toBeNull();
    expect(settings?.defaultChannels).toEqual(expect.arrayContaining(['sms']));
    expect(settings?.topics.some(topic => topic.id === 'security_login')).toBe(true);
  });

  it('updates notification settings and persists derived security alerts', async () => {
    const user = buildUser({ metadata: { security: { alerts: null } } });
    const update = jest.fn().mockResolvedValue(user);
    const prisma = buildPrisma(user, { update });
    const svc = new NotificationService({ prisma });

    const next = await svc.updateNotificationSettings('user-1', {
      defaultChannels: ['sms', 'push'],
      topics: [
        { id: 'security_login_alerts', enabled: false, channels: ['sms'], category: 'security', label: 'Security login', description: null },
        { id: 'task_assignments', enabled: true, channels: ['email'], category: 'operations', label: 'Tasks', description: 'tasks' },
      ],
      quietHours: { enabled: true, startHour: 21, endHour: 7, timezone: 'America/Los_Angeles' },
    });

    expect(next).not.toBeNull();
    expect(next?.defaultChannels).toEqual(['sms', 'push']);
    expect(next?.topics.find(topic => topic.id === 'security_login_alerts')?.enabled).toBe(false);
    expect(update).toHaveBeenCalledTimes(1);
    const payload = update.mock.calls[0]?.[0]?.data?.metadata;
    expect(payload).toBeDefined();
    expect(payload.notifications).toBeDefined();
    expect(payload.security.alerts.preferences[0].event).toBe('security_login_alerts');
  });

  it('returns registered devices when present on the user record', async () => {
    const now = new Date('2024-02-01T10:00:00Z');
    const user = buildUser({
      metadata: { notifications: { devices: [] } },
      notificationDevices: [
        {
          id: 'reg-1',
          label: 'MacBook',
          platform: 'web',
          status: 'active',
          lastUsedAt: now,
          updatedAt: now,
        },
      ],
    });
    const prisma = buildPrisma(user);
    const svc = new NotificationService({ prisma });

    const settings = await svc.getNotificationSettings('user-1');

    expect(settings?.devices).toHaveLength(1);
    expect(settings?.devices[0]).toMatchObject({ id: 'reg-1', label: 'MacBook', enabled: true });
  });

  it('registers a notification device and syncs metadata cache', async () => {
    const user = buildUser({ metadata: null });
    const devices = {
      findFirst: jest.fn().mockResolvedValue(null),
      create: jest.fn().mockResolvedValue({
        id: 'reg-2',
        label: 'Pixel',
        platform: 'android',
        status: 'active',
        lastUsedAt: new Date('2024-03-02T00:00:00Z'),
        updatedAt: new Date('2024-03-02T00:00:00Z'),
      }),
      findMany: jest.fn().mockResolvedValue([]),
    } as DeviceOverrides;
    const prisma = buildPrisma(user, { devices });
    const svc = new NotificationService({ prisma });

    const registered = await svc.registerNotificationDevice('user-1', {
      label: 'Pixel 8',
      platform: 'android',
      transport: 'web_push',
      fingerprint: 'fp-123',
      subscription: { endpoint: 'https://push.test/sub' },
      userAgent: 'Chrome/120',
    });

    expect(devices.create).toHaveBeenCalled();
    expect(prisma.user.update).toHaveBeenCalled();
    expect(registered).toMatchObject({ id: 'reg-2', enabled: true, label: 'Pixel' });
  });

  it('disables a registered device by id', async () => {
    const user = buildUser({ metadata: null });
    const devices = {
      findFirst: jest.fn().mockResolvedValue({ id: 'reg-3', userId: 'user-1' }),
      update: jest.fn().mockResolvedValue({ id: 'reg-3' }),
    } as DeviceOverrides;
    const prisma = buildPrisma(user, { devices });
    const svc = new NotificationService({ prisma });

    const result = await svc.disableNotificationDevice('user-1', 'reg-3');

    expect(result).toBe(true);
    expect(devices.update).toHaveBeenCalledWith({
      where: { id: 'reg-3' },
      data: expect.objectContaining({ status: 'revoked' }),
    });
  });

  it('returns null when the user is missing', async () => {
    const prisma = buildPrisma(null, { findUnique: jest.fn().mockResolvedValue(null) });
    const svc = new NotificationService({ prisma });

    await expect(svc.getNotificationSettings('missing')).resolves.toBeNull();
    await expect(svc.updateNotificationSettings('missing', { defaultChannels: ['email'] })).resolves.toBeNull();
    expect(prisma.user.update).not.toHaveBeenCalled();
  });
});
