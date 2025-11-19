import type { NotificationSettings, NotificationSettingsInput } from '@/types/notifications';

export interface INotificationService {
  loadSettings(): Promise<NotificationSettings>;
  updateSettings(input: NotificationSettingsInput): Promise<NotificationSettings>;
}
