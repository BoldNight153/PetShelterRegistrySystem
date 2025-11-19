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

  disableFactor(factorId: string): Promise<void> {
    return api.disableMfaFactor(factorId)
  }

  regenerateRecoveryCodes(): Promise<{ codes: string[]; expiresAt?: string | null }> {
    return api.regenerateRecoveryCodes()
  }

  updateAlerts(input: SecurityAlertSettings): Promise<SecurityAlertSettings> {
    return api.updateSecurityAlertPreferences(input)
  }

  updateRecovery(input: SecurityRecoverySettings): Promise<SecurityRecoverySettings> {
    return api.updateSecurityRecoveryContacts(input)
  }
}

export default new AccountSecurityAdapter()
