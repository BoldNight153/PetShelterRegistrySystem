import { configureStore } from '@reduxjs/toolkit'
import authReducer from './slices/authSlice'
import type { Services } from '@/services/defaults'
import { defaultServices } from '@/services/defaults'

function makeStore(services?: Partial<Services>) {
  const merged = { ...defaultServices, ...(services ?? {}) } as Services
  return configureStore({
    reducer: {
      auth: authReducer,
    },
    middleware: (gdm) => gdm({ thunk: { extraArgument: merged } }).concat(),
    devTools: process.env.NODE_ENV !== 'production',
  })
}

// Default store for tests and legacy imports — uses defaultServices
export const store = makeStore(defaultServices)

export function createStoreWithServices(services: Partial<Services>) {
  return makeStore(services)
}

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch

export default store
