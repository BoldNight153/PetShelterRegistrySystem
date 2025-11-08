import { render, screen, cleanup } from '@testing-library/react'
import { vi, test, expect } from 'vitest'
import { ServicesProvider } from '@/services/provider'
import { useServices } from '@/services/hooks'
import type { Services } from '@/services/defaults'

function Consumer() {
  const s = useServices()
  return <div data-testid="has-services">{typeof s.admin?.settings?.loadSettings === 'function' ? 'ok' : 'no'}</div>
}

test('ServicesProvider provides default services and allows overrides', () => {
  render(
    <ServicesProvider>
      <Consumer />
    </ServicesProvider>
  )
  expect(screen.getByTestId('has-services')).toHaveTextContent('ok')

  // remove the first render before rendering again to avoid duplicate test ids
  cleanup()

  const fakeLoad = vi.fn(async () => ({}))
  const fakeSave = vi.fn(async () => ({}))
  const override = {
    admin: { settings: { loadSettings: fakeLoad, saveSettings: fakeSave } },
  } satisfies Partial<Services>
  render(
    <ServicesProvider services={override}>
      <Consumer />
    </ServicesProvider>
  )
  expect(screen.getByTestId('has-services')).toHaveTextContent('ok')
})
