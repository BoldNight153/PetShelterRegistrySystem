import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useServices } from '@/services/hooks'
import type {
  AccountSecuritySnapshot,
  SecurityAlertSettings,
  SecurityMfaEnrollmentPrompt,
  SecurityMfaEnrollmentResult,
  SecurityRecoverySettings,
  SecuritySession,
} from '@/types/security-settings'
import type {
  ChangePasswordInput,
  ConfirmTotpEnrollmentInput,
  TotpEnrollmentInput,
  TrustSessionInput,
} from '@/services/interfaces/security.interface'

const ACCOUNT_SECURITY_KEY = ['accountSecurity'] as const
const ACCOUNT_SECURITY_SESSIONS_KEY = ['accountSecuritySessions'] as const

export function useAccountSecuritySnapshot() {
  const services = useServices()
  return useQuery<AccountSecuritySnapshot, Error>({
    queryKey: ACCOUNT_SECURITY_KEY,
    queryFn: () => services.security.loadSnapshot(),
  })
}

export function useAccountSecuritySessions() {
  const services = useServices()
  return useQuery<SecuritySession[], Error>({
    queryKey: ACCOUNT_SECURITY_SESSIONS_KEY,
    queryFn: () => services.security.listSessions(),
  })
}

export function useChangePassword() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<void, Error, ChangePasswordInput>({
    mutationFn: (input) => services.security.changePassword(input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}

export function useRevokeSession() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: (sessionId) => services.security.revokeSession(sessionId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_SESSIONS_KEY })
    },
  })
}

export function useRevokeAllSessions() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<void, Error>({
    mutationFn: () => services.security.revokeAllSessions(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_SESSIONS_KEY })
    },
  })
}

export function useTrustSession() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<void, Error, TrustSessionInput>({
    mutationFn: (input) => services.security.trustSession(input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_SESSIONS_KEY })
    },
  })
}

export function useStartTotpEnrollment() {
  const services = useServices()
  return useMutation<SecurityMfaEnrollmentPrompt, Error, TotpEnrollmentInput | undefined>({
    mutationFn: (input) => services.security.startTotpEnrollment(input),
  })
}

export function useConfirmTotpEnrollment() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<SecurityMfaEnrollmentResult, Error, ConfirmTotpEnrollmentInput>({
    mutationFn: (input) => services.security.confirmTotpEnrollment(input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}

export function useEnableMfaFactor() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: (factorId) => services.security.enableFactor(factorId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}

export function useDisableMfaFactor() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: (factorId) => services.security.disableFactor(factorId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}

export function useDeleteMfaFactor() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<void, Error, string>({
    mutationFn: (factorId) => services.security.deleteFactor(factorId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}

export function useRegenerateRecoveryCodes() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<{ codes: string[]; expiresAt?: string | null }, Error>({
    mutationFn: () => services.security.regenerateRecoveryCodes(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}

export function useUpdateSecurityAlerts() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<SecurityAlertSettings, Error, SecurityAlertSettings>({
    mutationFn: (input) => services.security.updateAlerts(input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}

export function useUpdateSecurityRecovery() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<SecurityRecoverySettings, Error, SecurityRecoverySettings>({
    mutationFn: (input) => services.security.updateRecovery(input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ACCOUNT_SECURITY_KEY })
    },
  })
}
