import { render, screen, cleanup } from '@testing-library/react'
/* eslint-disable @typescript-eslint/no-explicit-any */
import { vi, test, expect } from 'vitest'
import { ServicesProvider } from '@/services/provider'
import { useServices } from '@/services/hooks'

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
  const override: any = { admin: { settings: { loadSettings: fakeLoad, saveSettings: fakeSave } } }
  render(
    <ServicesProvider services={override}>
      <Consumer />
    </ServicesProvider>
  )
  expect(screen.getByTestId('has-services')).toHaveTextContent('ok')
})
