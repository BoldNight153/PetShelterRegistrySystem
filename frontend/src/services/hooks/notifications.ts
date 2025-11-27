import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useServices } from '@/services/hooks';
import type {
  NotificationSettings,
  NotificationSettingsInput,
  NotificationDevice,
  NotificationDeviceRegistrationInput,
} from '@/types/notifications';

const NOTIFICATION_SETTINGS_KEY = ['notificationSettings'] as const;

export function useNotificationSettings() {
  const services = useServices();
  return useQuery<NotificationSettings, Error>({
    queryKey: NOTIFICATION_SETTINGS_KEY,
    queryFn: () => services.notifications.loadSettings(),
  });
}

export function useUpdateNotificationSettings() {
  const services = useServices();
  const qc = useQueryClient();
  return useMutation<NotificationSettings, Error, NotificationSettingsInput>({
    mutationFn: (input) => services.notifications.updateSettings(input),
    onSuccess: (data) => {
      qc.setQueryData(NOTIFICATION_SETTINGS_KEY, data);
    },
  });
}

export function useRegisterNotificationDevice() {
  const services = useServices();
  const qc = useQueryClient();
  return useMutation<NotificationDevice, Error, NotificationDeviceRegistrationInput>({
    mutationFn: (input) => services.notifications.registerDevice(input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: NOTIFICATION_SETTINGS_KEY });
    },
  });
}

export function useDisableNotificationDevice() {
  const services = useServices();
  const qc = useQueryClient();
  return useMutation<void, Error, string>({
    mutationFn: (deviceId) => services.notifications.disableDevice(deviceId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: NOTIFICATION_SETTINGS_KEY });
    },
  });
}
