import type {
  AccountSecuritySnapshot,
  SecurityAlertSettings,
  SecurityMfaEnrollmentPrompt,
  SecurityMfaEnrollmentResult,
  SecurityRecoverySettings,
  SecuritySession,
} from '@/types/security-settings'

export type ChangePasswordInput = {
  currentPassword: string
  newPassword: string
  signOutOthers?: boolean
}

export type TotpEnrollmentInput = {
  label?: string
  issuer?: string
}

export type ConfirmTotpEnrollmentInput = {
  ticket: string
  code: string
}

export type TrustSessionInput = {
  sessionId: string
  trust: boolean
}

export interface IAccountSecurityService {
  loadSnapshot(): Promise<AccountSecuritySnapshot>
  listSessions(): Promise<SecuritySession[]>
  revokeSession(sessionId: string): Promise<void>
  revokeAllSessions(): Promise<void>
  trustSession(input: TrustSessionInput): Promise<void>
  changePassword(input: ChangePasswordInput): Promise<void>
  startTotpEnrollment(input?: TotpEnrollmentInput): Promise<SecurityMfaEnrollmentPrompt>
  confirmTotpEnrollment(input: ConfirmTotpEnrollmentInput): Promise<SecurityMfaEnrollmentResult>
  disableFactor(factorId: string): Promise<void>
  regenerateRecoveryCodes(): Promise<{ codes: string[]; expiresAt?: string | null }>
  updateAlerts(input: SecurityAlertSettings): Promise<SecurityAlertSettings>
  updateRecovery(input: SecurityRecoverySettings): Promise<SecurityRecoverySettings>
}
