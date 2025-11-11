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
	window.HTMLElement.prototype.scrollIntoView = vi.fn(() => {}) as unknown as typeof window.HTMLElement.prototype.scrollIntoView
}

// Global no-op implementations for browser dialog APIs used in the app
// Keeps test output quiet; individual tests can override these with spies if needed.
if (typeof window !== 'undefined') {
	window.alert = vi.fn() as unknown as typeof window.alert
	// confirm defaults to true to allow destructive flows in tests unless they stub it
	window.confirm = vi.fn(() => true) as unknown as typeof window.confirm
	// prompt returns null by default (user cancelled) — tests can stub to provide values
	window.prompt = vi.fn(() => null) as unknown as typeof window.prompt
}
