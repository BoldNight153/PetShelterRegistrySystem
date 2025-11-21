import type { LoginDeviceMetadata } from '@/types/auth'

const STORAGE_KEY = 'psrs.deviceFingerprint'
const FP_PREFIX = 'fpv1'

function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

function legacyHash(value: string): string {
  let hash = 0
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(i)
    hash |= 0
  }
  return Math.abs(hash).toString(16)
}

async function sha256(value: string): Promise<string> {
  try {
    if (typeof TextEncoder !== 'undefined' && globalThis.crypto?.subtle) {
      const encoded = new TextEncoder().encode(value)
      const digest = await globalThis.crypto.subtle.digest('SHA-256', encoded)
      return bufferToHex(digest)
    }
  } catch {
    // fall back
  }
  return legacyHash(value)
}

function safeNavigator(): Navigator | undefined {
  return typeof navigator !== 'undefined' ? navigator : undefined
}

function safeScreen(): Screen | undefined {
  return typeof screen !== 'undefined' ? screen : undefined
}

function safeStorage(): Storage | undefined {
  if (typeof window === 'undefined') return undefined
  try {
    return window.localStorage
  } catch {
    return undefined
  }
}

export async function computeDeviceFingerprint(): Promise<string | undefined> {
  const nav = safeNavigator()
  const scr = safeScreen()
  const timezone = typeof Intl !== 'undefined' ? Intl.DateTimeFormat().resolvedOptions().timeZone ?? '' : ''
  const uaData = (nav as any)?.userAgentData
  const parts = [
    nav?.userAgent ?? 'unknown',
    nav?.language ?? '',
    nav?.platform ?? '',
    uaData?.platform ?? '',
    uaData?.mobile ? 'mobile' : 'desktop',
    typeof nav?.hardwareConcurrency === 'number' ? String(nav.hardwareConcurrency) : '',
    typeof nav?.maxTouchPoints === 'number' ? String(nav.maxTouchPoints) : '',
    timezone,
    scr ? `${scr.width}x${scr.height}x${scr.colorDepth}` : '',
  ]
  const raw = parts.join('|')
  const hash = await sha256(raw)
  if (!hash) return undefined
  return `${FP_PREFIX}_${hash}`
}

export async function getDeviceFingerprint(forceRecompute = false): Promise<string | undefined> {
  const storage = safeStorage()
  if (!forceRecompute && storage) {
    const cached = storage.getItem(STORAGE_KEY)
    if (cached) return cached
  }
  const computed = await computeDeviceFingerprint()
  if (computed && storage) {
    try {
      storage.setItem(STORAGE_KEY, computed)
    } catch {
      // ignore quota errors
    }
  }
  return computed
}

export function clearDeviceFingerprintCache() {
  try {
    const storage = safeStorage()
    storage?.removeItem(STORAGE_KEY)
  } catch {
    // ignore
  }
}

export function guessDeviceLabel(): string {
  const nav = safeNavigator()
  const uaData = (nav as any)?.userAgentData
  if (uaData?.platform) {
    return `${uaData.platform}${uaData.mobile ? ' (mobile)' : ''}`
  }
  if (nav?.platform) return nav.platform
  return 'Browser session'
}

export function guessDevicePlatform(): string {
  const nav = safeNavigator()
  const uaData = (nav as any)?.userAgentData
  if (uaData?.platform) return uaData.platform
  if (nav?.platform) return nav.platform
  if (nav?.userAgent) {
    const match = nav.userAgent.match(/\(([^)]+)\)/)
    if (match?.[1]) return match[1]
    return nav.userAgent.split(' ')[0]
  }
  return 'unknown'
}

export async function buildDeviceMetadata(): Promise<Pick<LoginDeviceMetadata, 'deviceFingerprint' | 'deviceName' | 'devicePlatform'>> {
  const fingerprint = await getDeviceFingerprint()
  return {
    deviceFingerprint: fingerprint,
    deviceName: guessDeviceLabel(),
    devicePlatform: guessDevicePlatform(),
  }
}
