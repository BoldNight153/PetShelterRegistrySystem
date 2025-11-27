import { afterAll, beforeAll } from 'vitest'

let originalFetch: typeof fetch | undefined

function resolveUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (typeof URL !== 'undefined' && input instanceof URL) return input.toString()
  if (typeof Request !== 'undefined' && input instanceof Request) return input.url
  return String(input)
}

function isAuthModeRequest(urlString: string): boolean {
  try {
    const url = new URL(urlString, 'http://localhost')
    return url.pathname === '/auth/mode'
  } catch {
    return urlString === '/auth/mode'
  }
}

async function respondToAuthMode(): Promise<Response> {
  const payload = {
    authMode: 'session',
    cookies: { session: false, csrf: false },
    providers: {
      google: { configured: false },
      github: { configured: false },
    },
    csrf: { enabled: true },
    environment: 'vitest',
    issuedAt: new Date().toISOString(),
  }

  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

beforeAll(() => {
  originalFetch = globalThis.fetch?.bind(globalThis)
  if (!originalFetch) return

  globalThis.fetch = (async function mockableFetch(input: RequestInfo | URL, init?: RequestInit) {
    const urlString = resolveUrl(input)
    if (isAuthModeRequest(urlString)) {
      return respondToAuthMode()
    }
    return originalFetch!(input as RequestInfo, init)
  }) as typeof fetch
})

afterAll(() => {
  if (originalFetch) {
    globalThis.fetch = originalFetch
  }
})

export {}
