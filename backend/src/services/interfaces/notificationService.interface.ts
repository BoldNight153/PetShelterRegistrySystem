import type {
  NotificationSettings,
  NotificationSettingsInput,
} from '../../types/notificationSettings';

export interface INotificationService {
  getNotificationSettings(userId: string): Promise<NotificationSettings | null>;
  updateNotificationSettings(userId: string, payload: NotificationSettingsInput): Promise<NotificationSettings | null>;
}

export default INotificationService;
