import * as api from '@/lib/api';
import type { INotificationService } from '../interfaces/notifications.interface';
import type { NotificationSettings, NotificationSettingsInput } from '@/types/notifications';

export class NotificationAdapter implements INotificationService {
  loadSettings(): Promise<NotificationSettings> {
    return api.fetchNotificationSettings();
  }

  updateSettings(input: NotificationSettingsInput): Promise<NotificationSettings> {
    return api.updateNotificationSettings(input);
  }
}

export default new NotificationAdapter();
