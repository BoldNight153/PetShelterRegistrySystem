import { describe, it, expect } from 'vitest';
import { DEFAULT_NOTIFICATION_SETTINGS, normalizeNotificationSettings } from './notifications';

describe('normalizeNotificationSettings', () => {
  it('returns a cloned default when payload is missing', () => {
    const result = normalizeNotificationSettings(null);
    expect(result).toEqual(DEFAULT_NOTIFICATION_SETTINGS);
    expect(result).not.toBe(DEFAULT_NOTIFICATION_SETTINGS);
    expect(result.topics).not.toBe(DEFAULT_NOTIFICATION_SETTINGS.topics);
  });

  it('normalizes channels, topics, and quiet hours with safe fallbacks', () => {
    const raw: Record<string, unknown> = {
      defaultChannels: ['sms', 'fax'],
      topics: [
        { id: 'animal_matches', channels: ['push'], enabled: false },
        { id: 'custom_event', label: 'Custom event', channels: ['email', 'pager'], category: 'system', enabled: true },
      ],
      quietHours: { enabled: true, startHour: -4, endHour: 42, timezone: 'America/Los_Angeles' },
      digests: { enabled: true, frequency: 'daily', sendHourLocal: 30, includeSummary: false },
    };

    const result = normalizeNotificationSettings(raw);

  expect(result.defaultChannels).toEqual(['sms', 'email']);
    const updatedAnimal = result.topics.find((topic) => topic.id === 'animal_matches');
    expect(updatedAnimal?.channels).toEqual(['push']);
    expect(updatedAnimal?.enabled).toBe(false);

    const custom = result.topics.find((topic) => topic.id === 'custom_event');
    expect(custom).toMatchObject({
      label: 'Custom event',
      category: 'system',
      channels: ['email'],
    });

    expect(result.quietHours.startHour).toBe(0);
    expect(result.quietHours.endHour).toBe(23);
    expect(result.digests.sendHourLocal).toBe(23);
  });
});
