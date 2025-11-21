import { describe, expect, it } from 'vitest'
import reducer, { login, verifyMfaChallenge, clearPendingChallenge, logout } from './authSlice'
import type { LoginChallengePayload } from '@/types/auth'

describe('authSlice reducers', () => {
  const initialState = reducer(undefined, { type: '@@INIT' } as any)

  const makeChallenge = (): LoginChallengePayload => ({
    id: 'challenge-1',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    reason: 'mfa_required',
    defaultFactorId: 'factor-1',
    factors: [
      { id: 'factor-1', type: 'totp', label: 'Authenticator', lastUsedAt: null },
      { id: 'factor-backup', type: 'backup_codes', label: 'Backup codes', lastUsedAt: null },
    ],
    device: {
      fingerprint: 'fpv1_123',
      label: 'Browser session',
      platform: 'MacOS',
      trustRequested: false,
      trusted: false,
      allowTrust: true,
    },
  })

  it('stores pending challenge when login requires MFA', () => {
    const challenge = makeChallenge()
    const next = reducer(initialState, login.fulfilled({ challengeRequired: true, challenge }, '', { email: '', password: '' }))
    expect(next.pendingChallenge).toEqual(challenge)
    expect(next.user).toBeNull()
  })

  it('clears pending challenge and sets user on successful login', () => {
    const challenge = makeChallenge()
    const stateWithChallenge = { ...initialState, pendingChallenge: challenge }
    const user = { id: 'user-1', email: 'user@example.com' }
    const next = reducer(stateWithChallenge, login.fulfilled(user, '', { email: '', password: '' }))
    expect(next.user).toEqual(user)
    expect(next.pendingChallenge).toBeNull()
  })

  it('clears challenge when MFA verification succeeds', () => {
    const challenge = makeChallenge()
    const stateWithChallenge = { ...initialState, pendingChallenge: challenge }
    const user = { id: 'user-2', email: 'mfa@example.com' }
    const next = reducer(stateWithChallenge, verifyMfaChallenge.fulfilled(user, '', { challengeId: challenge.id }))
    expect(next.user).toEqual(user)
    expect(next.pendingChallenge).toBeNull()
  })

  it('clearPendingChallenge reducer resets challenge state', () => {
    const challenge = makeChallenge()
    const stateWithChallenge = { ...initialState, pendingChallenge: challenge }
    const next = reducer(stateWithChallenge, clearPendingChallenge())
    expect(next.pendingChallenge).toBeNull()
  })

  it('logout clears user and pending challenge', () => {
    const challenge = makeChallenge()
    const state = { ...initialState, pendingChallenge: challenge, user: { id: 'user-3' } }
    const next = reducer(state, logout.fulfilled(null, '', undefined))
    expect(next.user).toBeNull()
    expect(next.pendingChallenge).toBeNull()
  })
})
