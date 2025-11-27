import * as api from '@/lib/api';
import type { INotificationService } from '../interfaces/notifications.interface';
import type {
  NotificationSettings,
  NotificationSettingsInput,
  NotificationDevice,
  NotificationDeviceRegistrationInput,
} from '@/types/notifications';

export class NotificationAdapter implements INotificationService {
  loadSettings(): Promise<NotificationSettings> {
    return api.fetchNotificationSettings();
  }

  updateSettings(input: NotificationSettingsInput): Promise<NotificationSettings> {
    return api.updateNotificationSettings(input);
  }
  
  registerDevice(input: NotificationDeviceRegistrationInput): Promise<NotificationDevice> {
    return api.registerNotificationDevice(input);
  }
  
  disableDevice(deviceId: string): Promise<void> {
    return api.disableNotificationDevice(deviceId);
  }
}

export default new NotificationAdapter();
