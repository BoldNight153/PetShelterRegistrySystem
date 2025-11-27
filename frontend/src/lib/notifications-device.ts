import type { NotificationDevicePlatform, NotificationDeviceRegistrationInput } from '@/types/notifications'
import { getDeviceFingerprint, guessDeviceLabel } from '@/lib/device'

function inferPlatform(): NotificationDevicePlatform {
  if (typeof navigator === 'undefined') return 'unknown'
  const ua = navigator.userAgent.toLowerCase()
  if (/iphone|ipad|ipod|ios/.test(ua)) return 'ios'
  if (/android/.test(ua)) return 'android'
  return 'web'
}

function urlBase64ToUint8Array(value: string): Uint8Array {
  const padded = `${value}====`.slice(0, value.length + (4 - (value.length % 4)) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  const raw = typeof atob === 'function'
    ? atob(base64)
    : Buffer.from(base64, 'base64').toString('binary')
  const output = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i += 1) {
    output[i] = raw.charCodeAt(i)
  }
  return output
}

export function supportsPushNotifications(): boolean {
  if (typeof window === 'undefined') return false
  return 'Notification' in window && 'serviceWorker' in navigator && 'PushManager' in window
}

export async function buildNotificationRegistrationPayload(): Promise<NotificationDeviceRegistrationInput> {
  if (!supportsPushNotifications()) {
    throw new Error('Push notifications are not supported in this environment')
  }

  let permission = Notification.permission
  if (permission === 'default') {
    permission = await Notification.requestPermission()
  }
  if (permission !== 'granted') {
    throw new Error('Notification permission is required to register this device')
  }

  const registration = await navigator.serviceWorker.register('/notifications-sw.js')
  const existing = await registration.pushManager.getSubscription()

  const vapidKey = import.meta.env.VITE_PUBLIC_VAPID_KEY
  if (!vapidKey) {
    throw new Error('Push messaging is not configured (missing VITE_PUBLIC_VAPID_KEY)')
  }

  const subscription = existing ?? (await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapidKey),
  }))

  const fingerprint = await getDeviceFingerprint()
  return {
    label: guessDeviceLabel(),
    platform: inferPlatform(),
    transport: 'web_push',
    fingerprint,
    subscription: subscription.toJSON() as Record<string, unknown>,
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : undefined,
  }
}
