import '@testing-library/jest-dom/vitest'
import { afterEach, vi } from 'vitest'
import { cleanup } from '@testing-library/react'

afterEach(() => cleanup())

// Polyfill matchMedia for components using it (theme, sonner prefers-color-scheme, use-mobile hook)
if (!window.matchMedia) {
	window.matchMedia = vi.fn().mockImplementation((query: string) => ({
		matches: false,
		media: query,
		onchange: null,
		addListener: vi.fn(), // deprecated
		removeListener: vi.fn(), // deprecated
		addEventListener: vi.fn(),
		removeEventListener: vi.fn(),
		dispatchEvent: vi.fn(),
	}))
}

// Safe no-op scrollIntoView for jsdom environment to avoid errors from UI libraries
if (typeof window !== 'undefined' && typeof window.HTMLElement !== 'undefined') {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (window.HTMLElement.prototype as any).scrollIntoView = function scrollIntoView() {
    // intentionally empty for test environment
  }
}

// Global no-op implementations for browser dialog APIs used in the app
// Keeps test output quiet; individual tests can override these with spies if needed.
if (typeof window !== 'undefined') {
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	;(window as any).alert = vi.fn()
	// confirm defaults to true to allow destructive flows in tests unless they stub it
	;(window as any).confirm = vi.fn().mockImplementation(() => true)
	// prompt returns null by default (user cancelled) — tests can stub to provide values
	;(window as any).prompt = vi.fn().mockImplementation(() => null)
}
