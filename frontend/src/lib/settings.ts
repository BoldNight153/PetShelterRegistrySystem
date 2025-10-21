export type DrawerVariant = 'bottom' | 'top' | 'full'

const DEFAULT_AUTH_DRAWER_VARIANT: DrawerVariant = 'bottom'

export function getAuthDrawerVariant(): DrawerVariant {
  // First allow an env override from Vite
  const envVar = (import.meta as any)?.env?.VITE_AUTH_DRAWER_VARIANT as string | undefined
  if (envVar === 'bottom' || envVar === 'top' || envVar === 'full') {
    return envVar
  }
  // Then allow a localStorage override (helpful for quick UX trials)
  try {
    const ls = typeof window !== 'undefined' ? window.localStorage.getItem('authDrawerVariant') : null
    if (ls === 'bottom' || ls === 'top' || ls === 'full') {
      return ls
    }
  } catch {
    // ignore if storage not available
  }
  return DEFAULT_AUTH_DRAWER_VARIANT
}

export function setAuthDrawerVariant(variant: DrawerVariant) {
  try {
    window.localStorage.setItem('authDrawerVariant', variant)
  } catch {
    // ignore if storage not available
  }
}
