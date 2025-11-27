import type {
  NotificationSettings,
  NotificationSettingsInput,
  NotificationDevice,
  NotificationDeviceRegistrationInput,
} from '@/types/notifications'

export interface INotificationService {
  loadSettings(): Promise<NotificationSettings>;
  updateSettings(input: NotificationSettingsInput): Promise<NotificationSettings>;
  registerDevice(input: NotificationDeviceRegistrationInput): Promise<NotificationDevice>
  disableDevice(deviceId: string): Promise<void>
}
