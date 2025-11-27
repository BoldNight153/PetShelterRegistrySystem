import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import NotificationsSettingsPage from './notifications'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import type { Services } from '@/services/defaults'
import type { NotificationSettings, NotificationSettingsInput, NotificationTopicPreference, NotificationDevice } from '@/types/notifications'
import { DEFAULT_NOTIFICATION_SETTINGS } from '@/types/notifications'
import { buildNotificationRegistrationPayload, supportsPushNotifications } from '@/lib/notifications-device'

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

vi.mock('@/lib/notifications-device', () => ({
  buildNotificationRegistrationPayload: vi.fn(),
  supportsPushNotifications: vi.fn().mockReturnValue(true),
}))

let currentSettings: NotificationSettings
const loadSettingsMock = vi.fn(async () => currentSettings)
const updateSettingsMock = vi.fn(async (input: NotificationSettingsInput) => {
  currentSettings = applyPatch(currentSettings, input)
  return currentSettings
})
const registerDeviceMock = vi.fn(async () => mockRegisteredDevice())

const services: Partial<Services> = {
  notifications: {
    loadSettings: loadSettingsMock,
    updateSettings: updateSettingsMock,
    registerDevice: registerDeviceMock,
    disableDevice: vi.fn().mockResolvedValue(undefined),
  },
}

describe('NotificationsSettingsPage', () => {
  beforeEach(() => {
    currentSettings = buildSettings()
    loadSettingsMock.mockResolvedValue(currentSettings)
    updateSettingsMock.mockResolvedValue(currentSettings)
    registerDeviceMock.mockResolvedValue(mockRegisteredDevice())
    loadSettingsMock.mockClear()
    updateSettingsMock.mockClear()
    registerDeviceMock.mockClear()
    vi.mocked(buildNotificationRegistrationPayload).mockReset()
    vi.mocked(buildNotificationRegistrationPayload).mockResolvedValue({
      label: 'Browser session',
      transport: 'web_push',
      subscription: { endpoint: 'https://push.test' },
    })
    vi.mocked(supportsPushNotifications).mockReturnValue(true)
  })

  it('renders summary cards and topic rows when data loads', async () => {
    const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<NotificationsSettingsPage />, { wrapper })

    expect(await screen.findByText(/Notifications & alerts/i)).toBeInTheDocument()
    await waitFor(() => expect(loadSettingsMock).toHaveBeenCalledTimes(1))
    expect(await screen.findByText(/Topic coverage/i)).toBeInTheDocument()
    expect(await screen.findByText(/Security: Sign-in alerts/i)).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: /Toggle default channel Email/i })).toHaveAttribute('aria-pressed', 'true')
  })

  it('saves updated default channels', async () => {
  const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<NotificationsSettingsPage />, { wrapper })

    const pushToggle = await screen.findByRole('button', { name: /Toggle default channel Push/i })
    fireEvent.click(pushToggle)

    const saveButton = screen.getByRole('button', { name: /Save channel defaults/i })
    fireEvent.click(saveButton)

    await waitFor(() => expect(updateSettingsMock).toHaveBeenCalledTimes(1))
    const payload = updateSettingsMock.mock.calls[0][0]
    expect(payload.defaultChannels).toEqual(['email', 'push'])
    await waitFor(() => expect(saveButton).toBeDisabled())
  })

  it('updates topic channel overrides before saving', async () => {
  const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<NotificationsSettingsPage />, { wrapper })

    const smsToggle = await screen.findByRole('button', { name: /Toggle SMS for Task assignments/i })
    fireEvent.click(smsToggle)

    fireEvent.click(screen.getByRole('button', { name: /Save topic overrides/i }))

    await waitFor(() => expect(updateSettingsMock).toHaveBeenCalledTimes(1))
    const payload = updateSettingsMock.mock.calls[0][0]
    expect(payload.topics).toBeDefined()
    const taskTopic = payload.topics?.find((topic) => topic.id === 'task_assignments')
    expect(taskTopic?.channels).toContain('sms')
  })

  it('toggles trusted devices and persists the updated list', async () => {
    const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<NotificationsSettingsPage />, { wrapper })

    const deviceToggle = await screen.findByTestId('device-toggle-device-1')
    fireEvent.click(deviceToggle)

    const saveDevices = screen.getByRole('button', { name: /Save device preferences/i })
    fireEvent.click(saveDevices)

    await waitFor(() => expect(updateSettingsMock).toHaveBeenCalledTimes(1))
    const payload = updateSettingsMock.mock.calls[0][0]
    expect(payload.devices?.[0].enabled).toBe(false)
  })

  it('registers the current device when push is supported', async () => {
    const payload = {
      label: 'My Laptop',
      transport: 'web_push' as const,
      subscription: { endpoint: 'https://push.example' },
    }
    vi.mocked(buildNotificationRegistrationPayload).mockResolvedValue(payload)

    const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<NotificationsSettingsPage />, { wrapper })

    const registerButton = await screen.findByRole('button', { name: /register this device/i })
    fireEvent.click(registerButton)

    await waitFor(() => expect(registerDeviceMock).toHaveBeenCalledWith(payload))
  })
})

function buildSettings(): NotificationSettings {
  const base = JSON.parse(JSON.stringify(DEFAULT_NOTIFICATION_SETTINGS)) as NotificationSettings
  base.defaultChannels = ['email']
  base.topics = base.topics.map((topic) => cloneTopic(topic))
  base.devices = [
    {
      id: 'device-1',
      label: 'iPhone 15 Pro',
      platform: 'ios',
      enabled: true,
      lastUsedAt: '2024-02-01T12:00:00.000Z',
    },
  ]
  return base
}

function cloneTopic(topic: NotificationTopicPreference): NotificationTopicPreference {
  return { ...topic, channels: [...topic.channels] }
}

function applyPatch(settings: NotificationSettings, patch: NotificationSettingsInput): NotificationSettings {
  const next = JSON.parse(JSON.stringify(settings)) as NotificationSettings
  if (patch.defaultChannels) {
    next.defaultChannels = [...patch.defaultChannels]
  }
  if (patch.topics) {
    next.topics = next.topics.map((topic) => {
      const override = patch.topics?.find((entry) => entry.id === topic.id)
      if (!override) return topic
      return {
        ...topic,
        ...override,
        channels: override.channels ? [...override.channels] : topic.channels,
      }
    })
  }
  if (patch.digests) {
    next.digests = { ...next.digests, ...patch.digests }
  }
  if (patch.quietHours) {
    next.quietHours = { ...next.quietHours, ...patch.quietHours }
  }
  if (patch.criticalEscalations) {
    next.criticalEscalations = { ...next.criticalEscalations, ...patch.criticalEscalations }
  }
  if (patch.devices) {
    next.devices = patch.devices.map((device) => ({ ...device }))
  }
  return next
}

function mockRegisteredDevice(): NotificationDevice {
  return {
    id: 'device-registered',
    label: 'Browser session',
    platform: 'web',
    enabled: true,
    lastUsedAt: '2024-02-01T12:00:00.000Z',
  }
}
