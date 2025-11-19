import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NotificationAdapter } from '../notificationAdapter';
import type { NotificationSettings } from '@/types/notifications';
import type { NotificationSettingsInput } from '@/types/notifications';
import * as api from '@/lib/api';

vi.mock('@/lib/api', () => ({
  fetchNotificationSettings: vi.fn(),
  updateNotificationSettings: vi.fn(),
}));

const adapter = new NotificationAdapter();

describe('NotificationAdapter', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('loads notification settings through the API helper', async () => {
    const fakeSettings: NotificationSettings = {
      defaultChannels: ['email'],
      topics: [],
      digests: { enabled: true, frequency: 'daily', sendHourLocal: 9, timezone: 'UTC', includeSummary: true },
      quietHours: { enabled: false, startHour: 22, endHour: 7, timezone: 'UTC' },
      criticalEscalations: { smsFallback: true, backupEmail: null, pagerDutyWebhook: null },
      devices: [],
    };
    vi.mocked(api.fetchNotificationSettings).mockResolvedValue(fakeSettings);

    await expect(adapter.loadSettings()).resolves.toBe(fakeSettings);
    expect(api.fetchNotificationSettings).toHaveBeenCalledTimes(1);
  });

  it('updates notification settings through the API helper', async () => {
    const input: NotificationSettingsInput = {
      defaultChannels: ['sms', 'email'],
    };
    const response: NotificationSettings = {
      defaultChannels: ['sms', 'email'],
      topics: [],
      digests: { enabled: true, frequency: 'weekly', sendHourLocal: 10, timezone: 'UTC', includeSummary: false },
      quietHours: { enabled: true, startHour: 21, endHour: 6, timezone: 'UTC' },
      criticalEscalations: { smsFallback: true, backupEmail: 'ops@example.com', pagerDutyWebhook: null },
      devices: [],
    };
    vi.mocked(api.updateNotificationSettings).mockResolvedValue(response);

    await expect(adapter.updateSettings(input)).resolves.toBe(response);
    expect(api.updateNotificationSettings).toHaveBeenCalledWith(input);
  });
});
