import type {
  NotificationSettings,
  NotificationSettingsInput,
  NotificationDevice,
  NotificationDeviceRegistrationInput,
} from '../../types/notificationSettings';

export interface INotificationService {
  getNotificationSettings(userId: string): Promise<NotificationSettings | null>;
  updateNotificationSettings(userId: string, payload: NotificationSettingsInput): Promise<NotificationSettings | null>;
  registerNotificationDevice(userId: string, payload: NotificationDeviceRegistrationInput): Promise<NotificationDevice | null>;
  disableNotificationDevice(userId: string, deviceId: string): Promise<boolean>;
}

export default INotificationService;
