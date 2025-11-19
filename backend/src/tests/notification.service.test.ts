import { NotificationService, createDefaultNotificationSettings, type NotificationPrisma } from '../services/notificationService';

function buildUser(overrides: Record<string, any> = {}) {
  return {
    id: 'user-1',
    email: 'ops@example.com',
    metadata: overrides.metadata ?? null,
    ...overrides,
  } as any;
}

function buildPrisma(userRecord: any, overrides?: { findUnique?: jest.Mock; update?: jest.Mock }): NotificationPrisma {
  const findUnique = overrides?.findUnique ?? jest.fn().mockImplementation(async (args: { where: { id: string } }) => {
    if (!userRecord || args.where.id !== userRecord.id) return null;
    return userRecord;
  });
  const update = overrides?.update ?? jest.fn().mockResolvedValue(userRecord);
  return {
    user: {
      findUnique,
      update,
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
    expect(prisma.user.findUnique).toHaveBeenCalledWith({ where: { id: 'user-1' } });
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

  it('returns null when the user is missing', async () => {
    const prisma = buildPrisma(null, { findUnique: jest.fn().mockResolvedValue(null) });
    const svc = new NotificationService({ prisma });

    await expect(svc.getNotificationSettings('missing')).resolves.toBeNull();
    await expect(svc.updateNotificationSettings('missing', { defaultChannels: ['email'] })).resolves.toBeNull();
    expect(prisma.user.update).not.toHaveBeenCalled();
  });
});
