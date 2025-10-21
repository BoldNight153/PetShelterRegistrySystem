import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import userAdapter from '../userAdapter'

describe('UserAdapter.listSessions', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    // reset mock
    ;(global.fetch as any) = undefined
  })

  afterEach(() => {
    global.fetch = originalFetch
    vi.restoreAllMocks()
  })

  it('returns sessions on 200 response', async () => {
    const fake = [{ id: 's1', createdAt: '2025-10-19T00:00:00Z', ip: '1.2.3.4', userAgent: 'ua' }]
    global.fetch = vi.fn(async () => ({ ok: true, status: 200, json: async () => fake })) as any
    const res = await userAdapter.listSessions('u1')
    expect(res).toEqual(fake)
  })

  it('throws object with status 404 when endpoint not found', async () => {
    global.fetch = vi.fn(async () => ({ ok: false, status: 404 })) as any
    await expect(userAdapter.listSessions('u1')).rejects.toEqual({ status: 404 })
  })
})
