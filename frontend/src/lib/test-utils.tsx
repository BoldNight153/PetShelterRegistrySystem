import React, { PropsWithChildren } from 'react'
import { afterEach } from 'vitest'
import { cleanup, render } from '@testing-library/react'

// Clean up DOM between tests
afterEach(() => cleanup())

export function renderSimple(ui: React.ReactElement) {
  return render(ui)
}

export function mockFetchOnce(response: Partial<Response> & { body?: string } | Error) {
  const original = global.fetch
  const restore = () => { (global as any).fetch = original }
  if (response instanceof Error) {
    ;(global as any).fetch = vi.fn(async () => { throw response })
    return restore
  }
  const { status = 200, body = '', ok = status >= 200 && status < 300, headers } = response
  const res: Response = {
    ok,
    status,
    headers: new Headers(headers as any),
    redirected: false,
    statusText: String(status),
    type: 'basic',
    url: '/mock',
    clone() { return this },
    body: null,
    bodyUsed: false,
    async arrayBuffer() { return new ArrayBuffer(0) },
    async blob() { return new Blob() },
    async formData() { return new FormData() },
    async json() { return JSON.parse(body) },
    async text() { return body },
  } as unknown as Response
  ;(global as any).fetch = vi.fn(async () => res)
  return restore
}
