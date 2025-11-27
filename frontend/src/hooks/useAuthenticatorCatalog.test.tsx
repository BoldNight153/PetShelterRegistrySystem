import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { renderHook, waitFor } from '@testing-library/react'
import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { PropsWithChildren } from 'react'

import { ServicesProvider } from '@/services/provider'
import type { Services } from '@/services/defaults'
import type { AdminAuthenticatorCatalogRecord } from '@/services/interfaces/admin.interface'
import { useAuthenticatorCatalog, useAuthenticators } from './useAuthenticatorCatalog'

const catalogEntries: AdminAuthenticatorCatalogRecord[] = [
  { id: 'google', label: 'Google Authenticator', factorType: 'TOTP', isArchived: false },
  { id: 'backup_codes', label: 'Backup codes', factorType: 'BACKUP_CODES', isArchived: true },
]

const listMock = vi.fn<(options?: { includeArchived?: boolean }) => Promise<AdminAuthenticatorCatalogRecord[]>>()

function createWrapper() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const services: Partial<Services> = {
    admin: {
      settings: {
        loadSettings: vi.fn(),
        saveSettings: vi.fn(),
      } as Services['admin']['settings'],
      navigation: {} as Services['admin']['navigation'],
      authenticators: {
        list: listMock,
        create: vi.fn(),
        update: vi.fn(),
        archive: vi.fn(),
        restore: vi.fn(),
      } as Services['admin']['authenticators'],
    } as Services['admin'],
  }
  return ({ children }: PropsWithChildren) => (
    <ServicesProvider services={services}>
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </ServicesProvider>
  )
}

describe('useAuthenticatorCatalog hooks', () => {
  beforeEach(() => {
    listMock.mockReset()
    listMock.mockResolvedValue(catalogEntries)
  })

  it('fetches only active authenticators by default', async () => {
    const wrapper = createWrapper()
    const { result } = renderHook(() => useAuthenticatorCatalog(), { wrapper })

    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(listMock).toHaveBeenCalledWith({ includeArchived: false })
    expect(result.current.data).toEqual(catalogEntries)
  })

  it('exposes archived authenticators through useAuthenticators helper', async () => {
    const wrapper = createWrapper()
    const { result } = renderHook(() => useAuthenticators(), { wrapper })

    await waitFor(() => expect(result.current.authenticators?.length).toBe(2))
    expect(listMock).toHaveBeenCalledWith({ includeArchived: true })
    expect(result.current.findAuthenticatorById('backup_codes')).toMatchObject({ id: 'backup_codes', isArchived: true })
  })
})
