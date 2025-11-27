import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { LoginForm } from '@/components/auth/LoginForm'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import type { LoginChallengePayload, LoginChallengeResponse } from '@/types/auth'
import type { IAuthService } from '@/services/interfaces/auth.interface'
import { buildDeviceMetadata } from '@/lib/device'

vi.mock('sonner', () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
    message: vi.fn(),
  },
}))

vi.mock('@/lib/device', () => ({
  buildDeviceMetadata: vi.fn(),
}))

type MockDialogProps = {
  open: boolean
  challenge: LoginChallengePayload | null
  verifying: boolean
  error?: string | null
  errorDetails?: string[] | null
  onSubmit: (input: any) => void
  onCancel: () => void
  onExpired: () => void
}

const TOTP_BUTTON_LABEL = 'Submit mock TOTP'
const BACKUP_BUTTON_LABEL = 'Submit mock backup code'

vi.mock('@/components/auth/MfaChallengeDialog', () => {
  return {
    __esModule: true,
    default: (props: MockDialogProps) => {
      if (!props.open || !props.challenge) return null
      const defaultFactorId = props.challenge.defaultFactorId ?? props.challenge.factors[0]?.id
      return (
        <div role="dialog">
          <button
            type="button"
            onClick={() => props.onSubmit({
              method: 'totp',
              code: '654321',
              factorId: defaultFactorId,
              trustThisDevice: true,
            })}
          >
            {TOTP_BUTTON_LABEL}
          </button>
          <button
            type="button"
            onClick={() => props.onSubmit({ method: 'backup_code', backupCode: 'wolf-lime-jump-bird' })}
          >
            {BACKUP_BUTTON_LABEL}
          </button>
        </div>
      )
    },
  }
})

const buildDeviceMetadataMock = vi.mocked(buildDeviceMetadata)

const DEVICE_METADATA = {
  deviceFingerprint: 'fp_test',
  deviceName: 'Unit Test Browser',
  devicePlatform: 'Unit Test OS',
}

function createChallenge(overrides: Partial<LoginChallengePayload> = {}): LoginChallengePayload {
  const base: LoginChallengePayload = {
    id: 'challenge-123',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    reason: 'mfa_required',
    factors: [
      { id: 'factor-totp', type: 'totp', label: 'Authenticator app', lastUsedAt: new Date(Date.now() - 3_600_000).toISOString() },
      { id: 'factor-backup', type: 'backup_codes', label: 'Backup codes' },
    ],
    defaultFactorId: 'factor-totp',
    device: {
      fingerprint: 'fp_server',
      label: 'Server device',
      platform: 'Server platform',
      trustRequested: false,
      trusted: false,
      allowTrust: true,
    },
  }
  return {
    ...base,
    ...overrides,
    factors: overrides.factors ?? base.factors,
    device: { ...base.device, ...(overrides.device ?? {}) },
  }
}

function wrapChallenge(challenge: LoginChallengePayload): LoginChallengeResponse {
  return { challengeRequired: true, challenge }
}

function createAuthService(overrides: Partial<IAuthService>): IAuthService {
  const noop = async () => undefined
  return {
    login: vi.fn(noop),
    verifyMfaChallenge: vi.fn(noop),
    register: vi.fn(noop),
    logout: vi.fn(async () => {}),
    refresh: vi.fn(async () => null),
    me: vi.fn(async () => null),
    updateProfile: vi.fn(noop),
    ...overrides,
  }
}

beforeEach(() => {
  buildDeviceMetadataMock.mockResolvedValue(DEVICE_METADATA)
})

afterEach(() => {
  vi.clearAllMocks()
})

describe('LoginForm', () => {
  it('prompts for MFA when login returns a challenge and verifies codes with device metadata', async () => {
    const challenge = createChallenge()
    const loginMock = vi.fn(async () => wrapChallenge(challenge))
    const verifyMock = vi.fn(async () => ({ id: 'user-1', email: 'user@example.com' }))
    const authService = createAuthService({ login: loginMock, verifyMfaChallenge: verifyMock })
    const onSuccess = vi.fn()
    const { wrapper } = renderWithProviders(<div />, {
      services: { auth: authService },
      withRouter: true,
      initialEntries: ['/login'],
    })

    render(<LoginForm onSuccess={onSuccess} />, { wrapper })

    const emailInput = await screen.findByLabelText(/email/i)
    const passwordInput = await screen.findByLabelText(/password/i, { selector: 'input' })

    fireEvent.change(emailInput, { target: { value: 'user@example.com' } })
    fireEvent.change(passwordInput, { target: { value: 'Secret123!' } })

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await screen.findByRole('dialog')
    expect(screen.getByText(/Authenticator app/i)).toBeInTheDocument()
    expect(loginMock).toHaveBeenCalledWith({
      email: 'user@example.com',
      password: 'Secret123!',
      trustThisDevice: false,
      ...DEVICE_METADATA,
    })

    fireEvent.click(screen.getByRole('button', { name: TOTP_BUTTON_LABEL }))

    await waitFor(() => {
      expect(verifyMock).toHaveBeenCalledTimes(1)
    })

    expect(verifyMock).toHaveBeenCalledWith({
      challengeId: 'challenge-123',
      method: 'totp',
      code: '654321',
      factorId: 'factor-totp',
      trustThisDevice: true,
      ...DEVICE_METADATA,
    })
    expect(onSuccess).toHaveBeenCalled()
  })

  it('falls back to backup codes and reuses login trust preference when no primary factors exist', async () => {
    const challenge = createChallenge({
      reason: 'untrusted_device',
      factors: [{ id: 'factor-backup', type: 'backup_codes', label: 'Backup codes only' }],
      defaultFactorId: null,
    })
    const loginMock = vi.fn(async () => wrapChallenge(challenge))
    const verifyMock = vi.fn(async () => ({ id: 'user-2', email: 'user2@example.com' }))
    const authService = createAuthService({ login: loginMock, verifyMfaChallenge: verifyMock })
    const onSuccess = vi.fn()
    const { wrapper } = renderWithProviders(<div />, {
      services: { auth: authService },
      withRouter: true,
      initialEntries: ['/login'],
    })

    render(<LoginForm onSuccess={onSuccess} />, { wrapper })

    const emailInput = await screen.findByLabelText(/email/i)
    const passwordInput = await screen.findByLabelText(/password/i, { selector: 'input' })

    fireEvent.change(emailInput, { target: { value: 'user2@example.com' } })
    fireEvent.change(passwordInput, { target: { value: 'Secret456!' } })

    const trustToggle = screen.getByLabelText(/trust this device/i)
    fireEvent.click(trustToggle)

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await screen.findByRole('dialog')
    expect(screen.getByText(/Backup codes/i)).toBeInTheDocument()
    expect(loginMock).toHaveBeenCalledWith({
      email: 'user2@example.com',
      password: 'Secret456!',
      trustThisDevice: true,
      ...DEVICE_METADATA,
    })

    fireEvent.click(screen.getByRole('button', { name: BACKUP_BUTTON_LABEL }))

    await waitFor(() => {
      expect(verifyMock).toHaveBeenCalledTimes(1)
    })

    expect(verifyMock).toHaveBeenCalledWith({
      challengeId: 'challenge-123',
      method: 'backup_code',
      backupCode: 'wolf-lime-jump-bird',
      trustThisDevice: true,
      ...DEVICE_METADATA,
    })
    expect(onSuccess).toHaveBeenCalled()
  })

  it('surfaces structured error details returned by the login API', async () => {
    const errorPayload = { reason: 'manual_lock', until: new Date(Date.now() + 3_600_000).toISOString() }
    const loginMock = vi.fn(async () => {
      const err = new Error('account locked') as Error & { payload?: unknown }
      err.payload = errorPayload
      throw err
    })
    const authService = createAuthService({ login: loginMock })
    const { wrapper } = renderWithProviders(<div />, {
      services: { auth: authService },
      withRouter: true,
      initialEntries: ['/login'],
    })

    render(<LoginForm />, { wrapper })

    fireEvent.change(await screen.findByLabelText(/email/i), { target: { value: 'user3@example.com' } })
    fireEvent.change(await screen.findByLabelText(/password/i, { selector: 'input' }), { target: { value: 'Secret789!' } })

    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    await screen.findByText(/Sign-in failed/i)
    expect(screen.getByText(/Reason: manual_lock/i)).toBeInTheDocument()
    expect(screen.getByText(/Locked until/i)).toBeInTheDocument()
  })
})
