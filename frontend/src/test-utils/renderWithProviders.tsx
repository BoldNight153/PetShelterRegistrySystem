import React from 'react'
import { Provider } from 'react-redux'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ServicesProvider } from '@/services/provider'
import defaultStore, { createStoreWithServices } from '@/store/store'
import { MemoryRouter } from 'react-router-dom'
import type { Services } from '@/services/defaults'

type RenderOptions = {
  services?: Partial<Services>
  queryClient?: QueryClient
  withRouter?: boolean
  initialEntries?: string[]
}

export function renderWithProviders(
  _ui: React.ReactElement,
  { services, queryClient, withRouter = false, initialEntries = ['/dashboard'] }: RenderOptions = {}
) {
  const client = queryClient ?? new QueryClient()
  // If a services object is provided, create a local store wired with thunk.extraArgument
  const store = services ? createStoreWithServices(services) : defaultStore
  return {
    wrapper: ({ children }: { children?: React.ReactNode }) => (
      <Provider store={store}>
        <QueryClientProvider client={client}>
          <ServicesProvider services={services}>
            {withRouter ? <MemoryRouter initialEntries={initialEntries}>{children}</MemoryRouter> : children}
          </ServicesProvider>
        </QueryClientProvider>
      </Provider>
    ),
    queryClient: client,
  }
}
