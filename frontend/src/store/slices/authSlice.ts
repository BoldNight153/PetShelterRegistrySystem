import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import type { PayloadAction } from '@reduxjs/toolkit'
import type { RootState } from '../store'
import { defaultServices } from '@/services/defaults'

type User = any | null

export const login = createAsyncThunk('auth/login', async (input: { email: string; password: string }, thunkAPI) => {
  const services = (thunkAPI.extra as any) ?? defaultServices
  const data = await services.auth.login(input)
  return data
})

export const register = createAsyncThunk('auth/register', async (input: { email: string; password: string; name?: string }, thunkAPI) => {
  const services = (thunkAPI.extra as any) ?? defaultServices
  const data = await services.auth.register(input)
  return data
})

export const refresh = createAsyncThunk('auth/refresh', async (_: void, thunkAPI) => {
  const services = (thunkAPI.extra as any) ?? defaultServices
  const data = await services.auth.refresh()
  return data
})

export const logout = createAsyncThunk('auth/logout', async (_: void, thunkAPI) => {
  const services = (thunkAPI.extra as any) ?? defaultServices
  await services.auth.logout()
  return null
})

type AuthState = {
  user: User
  initializing: boolean
}

const initialState: AuthState = { user: null, initializing: true }

const slice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    setUser(state, action: PayloadAction<User>) {
      state.user = action.payload
    },
    setInitializing(state, action: PayloadAction<boolean>) {
      state.initializing = action.payload
    },
  },
  extraReducers: (builder) => {
    builder
  .addCase(login.fulfilled, (state, action) => { state.user = action.payload ?? null })
  .addCase(register.fulfilled, (state, action) => { state.user = action.payload ?? null })
  .addCase(refresh.fulfilled, (state, action) => { state.user = action.payload ?? null })
      .addCase(logout.fulfilled, (state) => { state.user = null })
  }
})

export const { setUser, setInitializing } = slice.actions

export const selectAuthUser = (state: RootState) => state.auth.user
export const selectAuthInitializing = (state: RootState) => state.auth.initializing

export default slice.reducer
