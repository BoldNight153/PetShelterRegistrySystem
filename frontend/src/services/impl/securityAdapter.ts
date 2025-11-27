import * as api from '../../lib/api'
import type {
  ChangePasswordInput,
  ConfirmTotpEnrollmentInput,
  IAccountSecurityService,
  TotpEnrollmentInput,
  TrustSessionInput,
} from '../interfaces/security.interface'
import type {
  AccountSecuritySnapshot,
  SecurityAlertSettings,
  SecurityMfaEnrollmentPrompt,
  SecurityMfaEnrollmentResult,
  SecurityRecoverySettings,
  SecuritySession,
} from '@/types/security-settings'

export class AccountSecurityAdapter implements IAccountSecurityService {
  loadSnapshot(): Promise<AccountSecuritySnapshot> {
    return api.fetchAccountSecuritySnapshot()
  }

  listAuthenticatorCatalog(options?: Parameters<typeof api.fetchSecurityAuthenticatorCatalog>[0]) {
    return api.fetchSecurityAuthenticatorCatalog(options)
  }

  listSessions(): Promise<SecuritySession[]> {
    return api.listAccountSecuritySessions()
  }

  revokeSession(sessionId: string): Promise<void> {
    return api.revokeAccountSecuritySession(sessionId)
  }

  revokeAllSessions(): Promise<void> {
    return api.revokeAllAccountSecuritySessions()
  }

  trustSession(input: TrustSessionInput): Promise<void> {
    return api.trustAccountSecuritySession(input.sessionId, input.trust)
  }

  changePassword(input: ChangePasswordInput): Promise<void> {
    return api.changeAccountPassword(input)
  }

  startTotpEnrollment(input?: TotpEnrollmentInput): Promise<SecurityMfaEnrollmentPrompt> {
    return api.startTotpEnrollment(input)
  }

  confirmTotpEnrollment(input: ConfirmTotpEnrollmentInput): Promise<SecurityMfaEnrollmentResult> {
    return api.confirmTotpEnrollment(input)
  }

  regenerateTotpFactor(factorId: string, input?: TotpEnrollmentInput): Promise<SecurityMfaEnrollmentPrompt> {
    return api.regenerateTotpFactor(factorId, input)
  }

  enableFactor(factorId: string): Promise<void> {
    return api.enableMfaFactor(factorId)
  }

  disableFactor(factorId: string): Promise<void> {
    return api.disableMfaFactor(factorId)
  }

  deleteFactor(factorId: string): Promise<void> {
    return api.deleteMfaFactor(factorId)
  }

  regenerateRecoveryCodes(factorId?: string): Promise<{ codes: string[]; expiresAt?: string | null }> {
    return api.regenerateRecoveryCodes(factorId)
  }

  updateAlerts(input: SecurityAlertSettings): Promise<SecurityAlertSettings> {
    return api.updateSecurityAlertPreferences(input)
  }

  updateRecovery(input: SecurityRecoverySettings): Promise<SecurityRecoverySettings> {
    return api.updateSecurityRecoveryContacts(input)
  }
}

export default new AccountSecurityAdapter()
