import { describe, it, expect, beforeEach, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import AccountSecuritySettingsPage from './security'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import type { Services } from '@/services/defaults'
import type { AccountSecuritySnapshot, SecurityMfaEnrollmentResult } from '@/types/security-settings'
import { DEFAULT_SECURITY_SNAPSHOT } from '@/types/security-settings'

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}))

function buildSnapshot(): AccountSecuritySnapshot {
  const snapshot = JSON.parse(JSON.stringify(DEFAULT_SECURITY_SNAPSHOT)) as AccountSecuritySnapshot
  snapshot.overview = {
    ...snapshot.overview,
    score: 82,
    tier: 'high',
    summary: 'All signals green',
    passwordHealth: 'strong',
    mfaEnabled: true,
    trustedDevices: 3,
    untrustedDevices: 1,
    pendingAlerts: 1,
    riskAlerts: [
      {
        id: 'risk-1',
        message: 'New device login from Seattle',
        severity: 'warning',
        createdAt: '2024-02-01T00:00:00.000Z',
      },
    ],
  }
  snapshot.password = {
    ...snapshot.password,
    history: [
      {
        id: 'pw-1',
        changedAt: '2024-01-10T00:00:00.000Z',
        location: 'Seattle, WA',
        client: 'Chrome',
      },
    ],
  }
  snapshot.mfa = {
    factors: [
      {
        id: 'factor-1',
        type: 'totp',
        label: 'Authenticator app',
        enabled: true,
        enrolledAt: '2024-01-01T00:00:00.000Z',
        lastUsedAt: '2024-01-15T00:00:00.000Z',
        devices: [],
        remainingCodes: 5,
        metadata: null,
      },
    ],
    recommendations: [],
  }
  snapshot.sessions = {
    summary: {
      activeCount: 2,
      trustedCount: 1,
      lastRotationAt: '2024-02-03T00:00:00.000Z',
      lastUntrustedAt: '2024-02-04T00:00:00.000Z',
    },
    list: [
      {
        id: 'session-1',
        device: 'MacBook Pro',
        platform: 'macOS',
        browser: 'Chrome 120',
        ipAddress: '203.0.113.1',
        location: 'Seattle, WA',
        createdAt: '2024-02-01T00:00:00.000Z',
        lastActiveAt: '2024-02-05T05:00:00.000Z',
        trusted: true,
        current: true,
        risk: 'low',
      },
    ],
  }
  snapshot.recovery = {
    primaryEmail: { type: 'email', value: 'primary@example.com', verified: true, lastVerifiedAt: '2024-01-05T00:00:00.000Z' },
    backupEmail: { type: 'email', value: 'backup@example.com', verified: false, lastVerifiedAt: null },
    sms: { type: 'sms', value: '+15551234567', verified: false, lastVerifiedAt: null },
    backupCodesRemaining: 5,
    lastCodesGeneratedAt: '2024-01-15T00:00:00.000Z',
    contacts: [
      { id: 'contact-1', name: 'On-call lead', email: 'oncall@example.com', phone: '+15559876543', verified: true },
    ],
  }
  snapshot.alerts = {
    defaultChannels: ['email'],
    preferences: [
      { event: 'login', label: 'Successful login', enabled: true, channels: ['email'] },
    ],
  }
  snapshot.events = [
    {
      id: 'event-1',
      action: 'auth.login',
      description: 'Login approved',
      severity: 'info',
      createdAt: '2024-02-05T00:00:00.000Z',
      ipAddress: '203.0.113.1',
      location: 'Seattle, WA',
      metadata: null,
    },
  ]
  return snapshot
}

const loadSnapshotMock = vi.fn(async () => buildSnapshot())
const listSessionsMock = vi.fn(async () => buildSnapshot().sessions.list)
const changePasswordMock = vi.fn(async () => undefined)
const revokeSessionMock = vi.fn(async () => undefined)
const revokeAllSessionsMock = vi.fn(async () => undefined)
const trustSessionMock = vi.fn(async () => undefined)
const startTotpMock = vi.fn(async () => ({ ticket: 'ticket', type: 'totp' as const }))
const confirmTotpMock = vi.fn(async (): Promise<SecurityMfaEnrollmentResult> => ({
  factor: {
    id: 'factor-2',
    type: 'totp',
    label: 'Authenticator app',
    enabled: true,
    enrolledAt: '2024-02-05T00:00:00.000Z',
    lastUsedAt: null,
    devices: [],
    remainingCodes: 10,
    metadata: null,
  },
  backupCodes: ['code-1', 'code-2'],
}))
const disableFactorMock = vi.fn(async () => undefined)
const deleteFactorMock = vi.fn(async () => undefined)
const regenerateCodesMock = vi.fn(async () => ({ codes: [] }))
const updateAlertsMock = vi.fn(async (input: AccountSecuritySnapshot['alerts']) => input)
const updateRecoveryMock = vi.fn(async (input: AccountSecuritySnapshot['recovery']) => input)

const services: Partial<Services> = {
  security: {
    loadSnapshot: loadSnapshotMock,
    listSessions: listSessionsMock,
    revokeSession: revokeSessionMock,
    revokeAllSessions: revokeAllSessionsMock,
    trustSession: trustSessionMock,
    changePassword: changePasswordMock,
    startTotpEnrollment: startTotpMock,
    confirmTotpEnrollment: confirmTotpMock,
    disableFactor: disableFactorMock,
    deleteFactor: deleteFactorMock,
    regenerateRecoveryCodes: regenerateCodesMock,
    updateAlerts: updateAlertsMock,
    updateRecovery: updateRecoveryMock,
  },
}

describe('AccountSecuritySettingsPage', () => {
  beforeEach(() => {
    const snapshot = buildSnapshot()
    loadSnapshotMock.mockResolvedValue(snapshot)
    listSessionsMock.mockResolvedValue(snapshot.sessions.list)
    changePasswordMock.mockResolvedValue(undefined)
    loadSnapshotMock.mockClear()
    listSessionsMock.mockClear()
    revokeSessionMock.mockClear()
    revokeAllSessionsMock.mockClear()
    trustSessionMock.mockClear()
    startTotpMock.mockClear()
    confirmTotpMock.mockClear()
    disableFactorMock.mockClear()
  deleteFactorMock.mockClear()
    regenerateCodesMock.mockClear()
    updateAlertsMock.mockClear()
    updateRecoveryMock.mockClear()
    changePasswordMock.mockClear()
  })

  it('renders the overview score and active factors', async () => {
    const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<AccountSecuritySettingsPage />, { wrapper })

  await waitFor(() => expect(loadSnapshotMock).toHaveBeenCalled())

  expect(await screen.findByText('82%')).toBeInTheDocument()
    expect(await screen.findByText(/New device login from Seattle/i)).toBeInTheDocument()
    const factorLabels = await screen.findAllByText(/Authenticator app/i)
    expect(factorLabels.length).toBeGreaterThan(0)
    expect(await screen.findByDisplayValue('primary@example.com')).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: /Manage notifications/i })).toBeInTheDocument()
  })

  it('submits password changes with the service payload', async () => {
  const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<AccountSecuritySettingsPage />, { wrapper })

    await screen.findByLabelText(/Current password/i)

    fireEvent.change(screen.getByLabelText(/Current password/i), { target: { value: 'old-pass' } })
  fireEvent.change(screen.getByLabelText(/^New password$/i), { target: { value: 'NewValidPass!23' } })
    fireEvent.change(screen.getByLabelText(/Confirm new password/i), { target: { value: 'NewValidPass!23' } })

    fireEvent.click(screen.getByRole('button', { name: /Update password/i }))

    await waitFor(() => expect(changePasswordMock).toHaveBeenCalledTimes(1))
    expect(changePasswordMock).toHaveBeenCalledWith({
      currentPassword: 'old-pass',
      newPassword: 'NewValidPass!23',
      signOutOthers: true,
    })
  })

  it('blocks weak passwords client-side before calling the service', async () => {
  const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<AccountSecuritySettingsPage />, { wrapper })

    const current = await screen.findByLabelText(/Current password/i)
    fireEvent.change(current, { target: { value: 'old-pass' } })
    fireEvent.change(screen.getByLabelText(/^New password$/i), { target: { value: 'short' } })
    fireEvent.change(screen.getByLabelText(/Confirm new password/i), { target: { value: 'short' } })

    const form = current.closest('form')
    expect(form).not.toBeNull()
    if (form) {
      fireEvent.submit(form)
    }

    await waitFor(() => expect(changePasswordMock).not.toHaveBeenCalled())
    const newPasswordInput = screen.getByLabelText(/^New password$/i)
    const newPasswordField = newPasswordInput.closest('div')?.parentElement
    expect(newPasswordField).not.toBeNull()
    if (newPasswordField) {
      expect(within(newPasswordField).getByText(/At least 8 characters/i)).toBeInTheDocument()
    }
  })

  it('passes the selected authenticator preset to the enrollment service', async () => {
    const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<AccountSecuritySettingsPage />, { wrapper })

    const startButton = await screen.findByRole('button', { name: /Select authenticator app/i })
    fireEvent.click(startButton)

    const googleButton = await screen.findByTestId('totp-preset-google')
    fireEvent.click(googleButton)

    await waitFor(() => expect(startTotpMock).toHaveBeenCalledWith({ label: 'Google Authenticator', issuer: 'Pet Shelter Registry' }))
  })

  it('deletes an authenticator after confirmation', async () => {
    const { wrapper } = renderWithProviders(<div />, { services, withRouter: true })
    render(<AccountSecuritySettingsPage />, { wrapper })

    const deleteButton = await screen.findByRole('button', { name: /Delete/i })
    fireEvent.click(deleteButton)

    const confirmButton = await screen.findByRole('button', { name: /Delete factor/i })
    fireEvent.click(confirmButton)

    await waitFor(() => expect(deleteFactorMock).toHaveBeenCalledWith('factor-1'))
  })
})
