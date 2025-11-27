import type {
  AccountSecuritySnapshot,
  SecurityAlertSettings,
  SecurityMfaEnrollmentPrompt,
  SecurityMfaEnrollmentResult,
  SecurityRecoverySettings,
  SecuritySession,
  SecurityAuthenticatorCatalogEntry,
  SecurityMfaFactorType,
} from '@/types/security-settings'

export type ChangePasswordInput = {
  currentPassword: string
  newPassword: string
  signOutOthers?: boolean
}

export type TotpEnrollmentInput = {
  label?: string
  issuer?: string
  accountName?: string
  catalogId?: string
}

export type ConfirmTotpEnrollmentInput = {
  ticket: string
  code: string
}

export type RegenerateTotpFactorInput = {
  factorId: string
  options?: TotpEnrollmentInput
}

export type TrustSessionInput = {
  sessionId: string
  trust: boolean
}

export type SecurityAuthenticatorCatalogFilter = {
  includeArchived?: boolean
  factorType?: SecurityMfaFactorType | Uppercase<SecurityMfaFactorType>
}

export interface IAccountSecurityService {
  loadSnapshot(): Promise<AccountSecuritySnapshot>
  listAuthenticatorCatalog(options?: SecurityAuthenticatorCatalogFilter): Promise<SecurityAuthenticatorCatalogEntry[]>
  listSessions(): Promise<SecuritySession[]>
  revokeSession(sessionId: string): Promise<void>
  revokeAllSessions(): Promise<void>
  trustSession(input: TrustSessionInput): Promise<void>
  changePassword(input: ChangePasswordInput): Promise<void>
  startTotpEnrollment(input?: TotpEnrollmentInput): Promise<SecurityMfaEnrollmentPrompt>
  confirmTotpEnrollment(input: ConfirmTotpEnrollmentInput): Promise<SecurityMfaEnrollmentResult>
  regenerateTotpFactor(factorId: string, input?: TotpEnrollmentInput): Promise<SecurityMfaEnrollmentPrompt>
  enableFactor(factorId: string): Promise<void>
  disableFactor(factorId: string): Promise<void>
  deleteFactor(factorId: string): Promise<void>
  regenerateRecoveryCodes(factorId?: string): Promise<{ codes: string[]; expiresAt?: string | null }>
  updateAlerts(input: SecurityAlertSettings): Promise<SecurityAlertSettings>
  updateRecovery(input: SecurityRecoverySettings): Promise<SecurityRecoverySettings>
}
