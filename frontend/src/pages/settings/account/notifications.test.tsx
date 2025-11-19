import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'

import NotificationsSettingsPage from './notifications'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import type { Services } from '@/services/defaults'
import type { NotificationSettings, NotificationSettingsInput, NotificationTopicPreference } from '@/types/notifications'
import { DEFAULT_NOTIFICATION_SETTINGS } from '@/types/notifications'

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

let currentSettings: NotificationSettings
const loadSettingsMock = vi.fn(async () => currentSettings)
const updateSettingsMock = vi.fn(async (input: NotificationSettingsInput) => {
  currentSettings = applyPatch(currentSettings, input)
  return currentSettings
})

const services: Partial<Services> = {
  notifications: {
    loadSettings: loadSettingsMock,
    updateSettings: updateSettingsMock,
  },
}

describe('NotificationsSettingsPage', () => {
  beforeEach(() => {
    currentSettings = buildSettings()
    loadSettingsMock.mockResolvedValue(currentSettings)
    updateSettingsMock.mockResolvedValue(currentSettings)
    loadSettingsMock.mockClear()
    updateSettingsMock.mockClear()
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
