import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import AdminSettingsPage from './settings'

vi.mock('@/lib/auth-context', () => {
  return {
    useAuth: () => ({ user: { email: 'admin@example.com', roles: ['system_admin'] } }),
  }
})

const saveSettingsMock = vi.fn().mockResolvedValue({ ok: true })
const loadSettingsMock = vi.fn().mockResolvedValue({
  security: {
    sessionMaxAgeMin: 60,
    requireEmailVerification: true,
    loginIpWindowSec: 60,
    loginIpLimit: 20,
    loginLockWindowSec: 900,
    loginLockThreshold: 5,
    loginLockDurationMin: 15,
    passwordHistoryLimit: 10,
  },
})

type SettingEntry = { key: string; value: unknown }
type SecuritySettings = {
  sessionMaxAgeMin: number
  requireEmailVerification: boolean
  loginIpWindowSec: number
  loginIpLimit: number
  loginLockWindowSec: number
  loginLockThreshold: number
  loginLockDurationMin: number
  passwordHistoryLimit: number
}

vi.mock('@/lib/api', async () => {
  return {
    // loadSettings has no parameters
    loadSettings: (...args: []) => loadSettingsMock(...args),
    saveSettings: (category: string, entries: SettingEntry[]) => saveSettingsMock(category, entries),
  } as {
    loadSettings: () => Promise<{ security: SecuritySettings }>
    saveSettings: (category: string, entries: SettingEntry[]) => Promise<{ ok: boolean }>
  }
})

describe('AdminSettingsPage (Security)', () => {
  beforeEach(() => {
    saveSettingsMock.mockClear()
    loadSettingsMock.mockClear()
  })

  it('saves security settings including new thresholds', async () => {
    render(<AdminSettingsPage />)

    // Wait for settings to load
    await waitFor(() => expect(loadSettingsMock).toHaveBeenCalledTimes(1))

    // Click Save Security
    const saveBtn = await screen.findByRole('button', { name: /save security/i })
    fireEvent.click(saveBtn)

    await waitFor(() => expect(saveSettingsMock).toHaveBeenCalled())

    const [category, entries] = saveSettingsMock.mock.calls.at(-1)!
    expect(category).toBe('security')
    const keys = (entries as Array<{ key: string; value: unknown }>).map(e => e.key)
    // Ensure all expected keys are present
    expect(keys).toEqual(expect.arrayContaining([
      'sessionMaxAgeMin',
      'requireEmailVerification',
      'loginIpWindowSec',
      'loginIpLimit',
      'loginLockWindowSec',
      'loginLockThreshold',
      'loginLockDurationMin',
      'passwordHistoryLimit',
    ]))
  })
})

describe('AdminSettingsPage (Access control)', () => {
  it('shows access denied for non-admins', async () => {
    // Reset module registry to apply a different mock
    vi.resetModules()
    vi.doMock('@/lib/auth-context', () => ({ useAuth: () => ({ user: { email: 'user@example.com', roles: [] } }) }))
    const { default: NonAdminSettings } = await import('./settings')
    render(<NonAdminSettings />)
    expect(await screen.findByText(/access denied/i)).toBeInTheDocument()
  })
})
