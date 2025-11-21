import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import type { PayloadAction } from '@reduxjs/toolkit'
import type { RootState } from '../store'
import { defaultServices } from '@/services/defaults'
import type { AuthLoginResult, LoginChallengePayload, LoginRequestInput, VerifyMfaChallengeInput } from '@/types/auth'
import { isAuthenticatedUser, isLoginChallengeResponse } from '@/types/auth'

type User = any | null

export const login = createAsyncThunk('auth/login', async (input: LoginRequestInput, thunkAPI) => {
  const services = (thunkAPI.extra as any) ?? defaultServices
  const data = await services.auth.login(input)
  return data
})

export const verifyMfaChallenge = createAsyncThunk('auth/verifyMfaChallenge', async (input: VerifyMfaChallengeInput, thunkAPI) => {
  const services = (thunkAPI.extra as any) ?? defaultServices
  const data = await services.auth.verifyMfaChallenge(input)
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
  pendingChallenge: LoginChallengePayload | null
}
const initialState: AuthState = { user: null, initializing: true, pendingChallenge: null }

function applyAuthPayload(state: AuthState, payload: AuthLoginResult) {
  if (isLoginChallengeResponse(payload)) {
    state.pendingChallenge = payload.challenge
    state.user = null
    return
  }
  if (isAuthenticatedUser(payload)) {
    state.user = payload
    state.pendingChallenge = null
    return
  }
  state.user = null
}

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
    clearPendingChallenge(state) {
      state.pendingChallenge = null
    },
  },
  extraReducers: (builder) => {
    builder
  .addCase(login.fulfilled, (state, action) => { applyAuthPayload(state, action.payload as AuthLoginResult) })
  .addCase(verifyMfaChallenge.fulfilled, (state, action) => { applyAuthPayload(state, action.payload as AuthLoginResult) })
  .addCase(register.fulfilled, (state, action) => { state.user = action.payload ?? null; state.pendingChallenge = null })
  .addCase(refresh.fulfilled, (state, action) => { state.user = action.payload ?? null; state.pendingChallenge = null })
      .addCase(logout.fulfilled, (state) => { state.user = null; state.pendingChallenge = null })
  }
})

export const { setUser, setInitializing, clearPendingChallenge } = slice.actions

export const selectAuthUser = (state: RootState) => state.auth.user
export const selectAuthInitializing = (state: RootState) => state.auth.initializing
export const selectPendingMfaChallenge = (state: RootState) => state.auth.pendingChallenge

export default slice.reducer
