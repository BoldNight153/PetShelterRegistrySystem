import { type ReactNode, useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertCircle,
  AlertTriangle,
  BellRing,
  Check,
  CheckCircle2,
  KeyRound,
  LogOut,
  RefreshCcw,
  Shield,
  Smartphone,
  Wifi,
  X,
} from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import PasswordInput from '@/components/ui/password-input'
import { Progress } from '@/components/ui/progress'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DEFAULT_SECURITY_SNAPSHOT,
  type AccountSecuritySnapshot,
  type SecurityAlertChannel,
  type SecurityAlertSettings,
  type SecurityMfaEnrollmentPrompt,
  type SecurityMfaFactor,
  type SecurityMfaFactorType,
  type SecurityRecoverySettings,
  type SecurityRiskSeverity,
  type SecuritySession,
  type SecurityEventEntry,
} from '@/types/security-settings'
import { passwordChangeSchema, type PasswordChangeValues } from '@/lib/validation'
import { evaluatePasswordRules, type PasswordRuleState } from '@/lib/passwordRules'
import {
  useAccountSecuritySessions,
  useAccountSecuritySnapshot,
  useChangePassword,
  useConfirmTotpEnrollment,
  useDisableMfaFactor,
  useRegenerateRecoveryCodes,
  useRevokeAllSessions,
  useRevokeSession,
  useStartTotpEnrollment,
  useTrustSession,
  useUpdateSecurityRecovery,
} from '@/services/hooks/security'

const CHANNEL_LABELS: Record<SecurityAlertChannel, string> = {
  email: 'Email',
  sms: 'SMS',
  push: 'Push notification',
  in_app: 'In-app',
}

const MFA_TYPE_LABELS: Record<SecurityMfaFactorType, string> = {
  totp: 'Authenticator app',
  sms: 'SMS code',
  push: 'Push approval',
  hardware_key: 'Hardware key',
  backup_codes: 'Backup codes',
}

const SEVERITY_VARIANT: Record<SecurityRiskSeverity, 'default' | 'secondary' | 'destructive'> = {
  info: 'secondary',
  warning: 'default',
  critical: 'destructive',
}

type PasswordFormState = PasswordChangeValues & {
  signOutOthers: boolean
}

type PasswordFieldErrors = Partial<Record<keyof PasswordChangeValues, string[]>>

type CodesModalState = {
  open: boolean
  codes: string[]
  expiresAt?: string | null
}

const INITIAL_PASSWORD_FORM: PasswordFormState = {
  currentPassword: '',
  newPassword: '',
  confirmPassword: '',
  signOutOthers: true,
}

const INITIAL_CODES_MODAL: CodesModalState = {
  open: false,
  codes: [],
  expiresAt: null,
}

function cloneRecovery(value: SecurityRecoverySettings | undefined): SecurityRecoverySettings {
  return JSON.parse(JSON.stringify(value ?? DEFAULT_SECURITY_SNAPSHOT.recovery)) as SecurityRecoverySettings
}

function relativeTime(value?: string | null): string {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return formatDistanceToNow(date, { addSuffix: true })
}

function absoluteTime(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return format(date, 'MMM d, yyyy • h:mmaaa')
}

function formatSessionLocation(session: SecuritySession): string {
  if (session.location) return session.location
  if (session.ipAddress) return session.ipAddress
  return 'Unknown location'
}

function buildDeviceLabel(session: SecuritySession): string {
  const parts = [session.device, session.browser?.split(' ')[0]].filter(Boolean)
  return parts.join(' • ') || 'Device'
}

export default function AccountSecuritySettingsPage() {
  const snapshotQuery = useAccountSecuritySnapshot()
  const sessionsQuery = useAccountSecuritySessions()

  const changePassword = useChangePassword()
  const revokeSession = useRevokeSession()
  const revokeAllSessions = useRevokeAllSessions()
  const trustSession = useTrustSession()
  const startTotpEnrollment = useStartTotpEnrollment()
  const confirmTotpEnrollment = useConfirmTotpEnrollment()
  const disableMfaFactor = useDisableMfaFactor()
  const regenerateCodes = useRegenerateRecoveryCodes()
  const updateRecovery = useUpdateSecurityRecovery()

  const [passwordForm, setPasswordForm] = useState<PasswordFormState>(() => ({ ...INITIAL_PASSWORD_FORM }))
  const [passwordAttempted, setPasswordAttempted] = useState(false)
  const [passwordError, setPasswordError] = useState<string | null>(null)

  const resetPasswordForm = () => {
    setPasswordForm({ ...INITIAL_PASSWORD_FORM })
    setPasswordAttempted(false)
    setPasswordError(null)
  }
  const [totpPrompt, setTotpPrompt] = useState<SecurityMfaEnrollmentPrompt | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [totpDialogOpen, setTotpDialogOpen] = useState(false)
  const [codesModal, setCodesModal] = useState<CodesModalState>(() => ({ ...INITIAL_CODES_MODAL }))
  const [sessionAction, setSessionAction] = useState<string | null>(null)
  const [recoveryDraft, setRecoveryDraft] = useState<SecurityRecoverySettings>(() => cloneRecovery(undefined))

  useEffect(() => {
    if (!snapshotQuery.data) return
    setRecoveryDraft(cloneRecovery(snapshotQuery.data.recovery))
  }, [snapshotQuery.data])

  const snapshot = snapshotQuery.data ?? DEFAULT_SECURITY_SNAPSHOT
  const sessions = sessionsQuery.data ?? snapshot.sessions.list
  const overview = snapshot.overview

  const loading = snapshotQuery.isLoading && !snapshotQuery.data
  const error = snapshotQuery.error as Error | null

  const eventFeed = useMemo(() => snapshot.events.slice(0, 8), [snapshot.events])
  const passwordHistory = useMemo(() => snapshot.password.history.slice(0, 5), [snapshot.password.history])
  const passwordValidation = useMemo(() => passwordChangeSchema.safeParse(passwordForm), [passwordForm])
  const passwordFieldErrors = useMemo<PasswordFieldErrors>(() => (
    passwordValidation.success ? {} : passwordValidation.error.flatten().fieldErrors
  ), [passwordValidation])
  const passwordRules = useMemo<PasswordRuleState[]>(() => evaluatePasswordRules(passwordForm.newPassword), [passwordForm.newPassword])
  const canSubmitPassword = passwordValidation.success

  const handlePasswordSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setPasswordAttempted(true)
    setPasswordError(null)
    const validation = passwordChangeSchema.safeParse(passwordForm)
    if (!validation.success) {
      return
    }
    try {
      await changePassword.mutateAsync({
        currentPassword: passwordForm.currentPassword,
        newPassword: passwordForm.newPassword,
        signOutOthers: passwordForm.signOutOthers,
      })
      resetPasswordForm()
      toast.success('Password updated successfully')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to change password'
      setPasswordError(message)
      toast.error(message)
    }
  }

  const handleRevokeSession = async (sessionId: string) => {
    try {
      setSessionAction(sessionId)
      await revokeSession.mutateAsync(sessionId)
      toast.success('Session revoked')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to revoke session'
      toast.error(message)
    } finally {
      setSessionAction(null)
    }
  }

  const handleTrustToggle = async (session: SecuritySession) => {
    try {
      setSessionAction(session.id)
      await trustSession.mutateAsync({ sessionId: session.id, trust: !session.trusted })
      toast.success(session.trusted ? 'Session marked untrusted' : 'Session marked trusted')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update session trust'
      toast.error(message)
    } finally {
      setSessionAction(null)
    }
  }

  const handleRevokeAll = async () => {
    try {
      setSessionAction('*')
      await revokeAllSessions.mutateAsync()
      toast.success('All other sessions revoked')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to revoke sessions'
      toast.error(message)
    } finally {
      setSessionAction(null)
    }
  }

  const handleStartTotp = async () => {
    try {
      const prompt = await startTotpEnrollment.mutateAsync(undefined)
      setTotpPrompt(prompt)
      setTotpDialogOpen(true)
      setTotpCode('')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to start MFA enrollment'
      toast.error(message)
    }
  }

  const handleConfirmTotp = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!totpPrompt) return
    try {
      await confirmTotpEnrollment.mutateAsync({ ticket: totpPrompt.ticket, code: totpCode })
      toast.success('Authenticator app connected')
      setTotpDialogOpen(false)
      setTotpPrompt(null)
      setTotpCode('')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to confirm MFA enrollment'
      toast.error(message)
    }
  }

  const handleDisableFactor = async (factor: SecurityMfaFactor) => {
    try {
      await disableMfaFactor.mutateAsync(factor.id)
      toast.success(`${factor.label} disabled`)
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to disable factor'
      toast.error(message)
    }
  }

  const handleRegenerateCodes = async () => {
    try {
      const result = await regenerateCodes.mutateAsync()
      setCodesModal({ open: true, codes: result.codes ?? [], expiresAt: result.expiresAt })
      toast.success('Backup codes regenerated')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to regenerate codes'
      toast.error(message)
    }
  }

  const saveRecovery = async () => {
    try {
      await updateRecovery.mutateAsync(recoveryDraft)
      toast.success('Recovery contacts saved')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unable to save recovery contacts'
      toast.error(message)
    }
  }

  const updateRecoveryValue = (key: 'primaryEmail' | 'backupEmail' | 'sms', value: string) => {
    setRecoveryDraft((prev) => {
      const base = prev[key] ?? {
        type: key === 'sms' ? 'sms' : 'email',
        value: '',
        verified: false,
        lastVerifiedAt: null,
      }
      return {
        ...prev,
        [key]: { ...base, value },
      }
    })
  }

  if (loading) {
    return <SecurityPageSkeleton />
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <Shield className="text-primary" />
        <div>
          <h1 className="text-2xl font-semibold">Account security</h1>
          <p className="text-sm text-muted-foreground">Review password health, MFA coverage, trusted sessions, and recovery safeguards sourced directly from the auth service.</p>
        </div>
        <Badge variant="outline" className="ml-auto">Account &amp; Profile</Badge>
      </div>

      {error ? (
        <Alert variant="destructive">
          <AlertTitle>Unable to load security data</AlertTitle>
          <AlertDescription>{error.message}</AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>Security posture</CardTitle>
          <CardDescription>Score updates after each password, MFA, or session change.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-6 lg:grid-cols-[2fr,3fr]">
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="text-4xl font-bold">{overview.score}%</div>
                <div className="space-y-1 text-sm text-muted-foreground">
                  <div>{overview.summary}</div>
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <Badge>{overview.tier.toUpperCase()} confidence</Badge>
                    <span>{overview.mfaEnabled ? 'MFA enforced' : 'MFA pending'}</span>
                  </div>
                </div>
              </div>
              <Progress value={overview.score} className="h-2" />
              <dl className="grid gap-4 sm:grid-cols-2">
                <div>
                  <dt className="text-xs uppercase tracking-wide text-muted-foreground">Password freshness</dt>
                  <dd className="text-sm font-medium">{relativeTime(overview.lastPasswordChange)}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-muted-foreground">Last anomaly</dt>
                  <dd className="text-sm font-medium">{relativeTime(overview.lastAnomalyAt)}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-muted-foreground">Trusted devices</dt>
                  <dd className="text-sm font-medium">{overview.trustedDevices} / {overview.trustedDevices + overview.untrustedDevices}</dd>
                </div>
                <div>
                  <dt className="text-xs uppercase tracking-wide text-muted-foreground">Open alerts</dt>
                  <dd className="text-sm font-medium">{overview.pendingAlerts}</dd>
                </div>
              </dl>
            </div>
            <div className="rounded-lg border p-4 space-y-4">
              <div className="flex items-center gap-2">
                <BellRing className="h-4 w-4 text-primary" />
                <div className="font-medium">Urgent follow-ups</div>
              </div>
              {overview.riskAlerts.length === 0 ? (
                <p className="text-sm text-muted-foreground">No active risk alerts. You will see device, password, or MFA anomalies here.</p>
              ) : (
                <ul className="space-y-3 text-sm">
                  {overview.riskAlerts.slice(0, 3).map((alert) => (
                    <li key={alert.id} className="rounded border p-3">
                      <div className="flex items-center gap-2">
                        <Badge variant={SEVERITY_VARIANT[alert.severity]} className="uppercase tracking-wide text-[10px]">{alert.severity}</Badge>
                        <span className="font-medium">{alert.message}</span>
                      </div>
                      <div className="text-xs text-muted-foreground mt-1">Detected {relativeTime(alert.createdAt)}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid gap-6 xl:grid-cols-[2fr,1fr]">
        <div className="space-y-6">
          <PasswordCard
            passwordForm={passwordForm}
            onChange={setPasswordForm}
            onSubmit={handlePasswordSubmit}
            onReset={resetPasswordForm}
            policy={snapshot.password.policy}
            history={passwordHistory}
            saving={changePassword.isPending}
            error={passwordError}
            validationErrors={passwordFieldErrors}
            showValidation={passwordAttempted}
            requirements={passwordRules}
            canSubmit={canSubmitPassword}
          />

          <MfaCard
            factors={snapshot.mfa.factors}
            recommendations={snapshot.mfa.recommendations}
            onStartTotp={handleStartTotp}
            onRegenerateCodes={handleRegenerateCodes}
            onDisableFactor={handleDisableFactor}
            disablePending={disableMfaFactor.isPending}
            regeneratePending={regenerateCodes.isPending}
            startPending={startTotpEnrollment.isPending}
          />

          <SessionsCard
            summary={snapshot.sessions.summary}
            sessions={sessions}
            onRevoke={handleRevokeSession}
            onRevokeAll={handleRevokeAll}
            onTrustToggle={handleTrustToggle}
            sessionAction={sessionAction}
          />
        </div>

        <div className="space-y-6">
          <RecoveryCard
            recovery={recoveryDraft}
            onChannelChange={updateRecoveryValue}
            onSave={saveRecovery}
            saving={updateRecovery.isPending}
            onRegenerateCodes={handleRegenerateCodes}
            regeneratePending={regenerateCodes.isPending}
          />

          <AlertsPointerCard alerts={snapshot.alerts} />

          <EventsCard events={eventFeed} />
        </div>
      </div>

      <TotpDialog
        open={totpDialogOpen}
        prompt={totpPrompt}
        code={totpCode}
        submitting={confirmTotpEnrollment.isPending}
        onCodeChange={setTotpCode}
        onOpenChange={setTotpDialogOpen}
        onSubmit={handleConfirmTotp}
      />

      <BackupCodesDialog
        modal={codesModal}
        onOpenChange={(open) => setCodesModal((prev) => ({ ...prev, open }))}
      />
    </div>
  )
}

function PasswordCard({
  passwordForm,
  onChange,
  onSubmit,
  onReset,
  policy,
  history,
  saving,
  error,
  validationErrors,
  showValidation,
  requirements,
  canSubmit,
}: {
  passwordForm: PasswordFormState
  onChange: React.Dispatch<React.SetStateAction<PasswordFormState>>
  onSubmit: (event: React.FormEvent<HTMLFormElement>) => void
  onReset: () => void
  policy: AccountSecuritySnapshot['password']['policy']
  history: AccountSecuritySnapshot['password']['history']
  saving: boolean
  error: string | null
  validationErrors: PasswordFieldErrors
  showValidation: boolean
  requirements: PasswordRuleState[]
  canSubmit: boolean
}) {
  const fieldInvalid = (field: keyof PasswordChangeValues) => showValidation && Boolean(validationErrors[field]?.length)
  const fieldError = (field: keyof PasswordChangeValues) => (showValidation ? validationErrors[field]?.[0] ?? null : null)
  const confirmSatisfied = Boolean(passwordForm.newPassword && passwordForm.confirmPassword && passwordForm.newPassword === passwordForm.confirmPassword)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Passwords &amp; policy</CardTitle>
        <CardDescription>Enforce strong passphrases then rotate on a cadence.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error ? (
          <Alert variant="destructive">
            <AlertTitle>Update failed</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        <form className="grid gap-4 md:grid-cols-2" onSubmit={onSubmit} noValidate>
          <div className="space-y-2">
            <Label htmlFor="current-password">Current password</Label>
            <PasswordInput
              id="current-password"
              autoComplete="current-password"
              value={passwordForm.currentPassword}
              onChange={(event) => onChange((prev) => ({ ...prev, currentPassword: event.target.value }))}
              className={fieldInvalid('currentPassword') ? 'border-destructive ring-1 ring-destructive' : undefined}
              aria-invalid={fieldInvalid('currentPassword') || undefined}
            />
            {fieldError('currentPassword') ? (
              <p className="text-sm text-destructive">{fieldError('currentPassword')}</p>
            ) : null}
          </div>
          <div className="space-y-2">
            <Label htmlFor="new-password">New password</Label>
            <PasswordInput
              id="new-password"
              autoComplete="new-password"
              value={passwordForm.newPassword}
              onChange={(event) => onChange((prev) => ({ ...prev, newPassword: event.target.value }))}
              className={fieldInvalid('newPassword') ? 'border-destructive ring-1 ring-destructive' : undefined}
              aria-invalid={fieldInvalid('newPassword') || undefined}
            />
            {fieldError('newPassword') ? (
              <p className="text-sm text-destructive">{fieldError('newPassword')}</p>
            ) : null}
          </div>
          <div className="space-y-2">
            <Label htmlFor="confirm-password">Confirm new password</Label>
            <PasswordInput
              id="confirm-password"
              autoComplete="new-password"
              value={passwordForm.confirmPassword}
              onChange={(event) => onChange((prev) => ({ ...prev, confirmPassword: event.target.value }))}
              className={fieldInvalid('confirmPassword') ? 'border-destructive ring-1 ring-destructive' : undefined}
              aria-invalid={fieldInvalid('confirmPassword') || undefined}
            />
            {fieldError('confirmPassword') ? (
              <p className="text-sm text-destructive">{fieldError('confirmPassword')}</p>
            ) : null}
          </div>
          <div className="flex items-center gap-3 pt-6">
            <Checkbox
              id="password-signout"
              checked={passwordForm.signOutOthers}
              onCheckedChange={(checked) => onChange((prev) => ({ ...prev, signOutOthers: Boolean(checked) }))}
            />
            <Label htmlFor="password-signout" className="text-sm">Sign out other sessions after changing my password</Label>
          </div>
          <div className="md:col-span-2 flex flex-wrap gap-3">
            <Button type="submit" disabled={saving || !canSubmit}>
              {saving ? 'Updating…' : 'Update password'}
            </Button>
            <Button type="button" variant="outline" onClick={onReset} disabled={saving}>
              Reset form
            </Button>
          </div>
        </form>
        <div className="text-sm text-muted-foreground">
          <p className="font-medium">Password requirements:</p>
          <ul className="mt-1 space-y-1">
            {requirements.map((rule) => (
              <li key={rule.id} className="flex items-center gap-2">
                {rule.pass ? (
                  <Check className="h-4 w-4 text-success" />
                ) : (
                  <X className="h-4 w-4 text-destructive" />
                )}
                <span className={rule.pass ? 'text-success' : 'text-muted-foreground'}>{rule.label}</span>
              </li>
            ))}
            <li className="flex items-center gap-2">
              {confirmSatisfied ? (
                <Check className="h-4 w-4 text-success" />
              ) : (
                <X className="h-4 w-4 text-destructive" />
              )}
              <span className={confirmSatisfied ? 'text-success' : 'text-muted-foreground'}>
                Password and confirmation must match
              </span>
            </li>
          </ul>
        </div>
        <Separator />
        <div className="grid gap-4 md:grid-cols-2 text-sm text-muted-foreground">
          <div>
            <div className="font-medium text-foreground mb-2">Policy summary</div>
            <ul className="list-disc pl-5 space-y-1">
              <li>Minimum length {policy.minLength} characters</li>
              <li>Requires uppercase, lowercase, number, and symbol</li>
              <li>Expires every {policy.expiryDays ?? 365} days</li>
              <li>Remembers last {policy.historyCount} passwords</li>
            </ul>
          </div>
          <div>
            <div className="font-medium text-foreground mb-2">Recent changes</div>
            <ul className="space-y-1">
              {history.length === 0 ? (
                <li className="text-muted-foreground">No password changes recorded yet.</li>
              ) : history.map((entry) => (
                <li key={entry.id} className="flex items-center justify-between">
                  <span>{absoluteTime(entry.changedAt)}</span>
                  <span className="text-xs">{entry.location || '—'}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function MfaCard({
  factors,
  recommendations,
  onStartTotp,
  onRegenerateCodes,
  onDisableFactor,
  disablePending,
  regeneratePending,
  startPending,
}: {
  factors: SecurityMfaFactor[]
  recommendations: AccountSecuritySnapshot['mfa']['recommendations']
  onStartTotp: () => void
  onRegenerateCodes: () => void
  onDisableFactor: (factor: SecurityMfaFactor) => void
  disablePending: boolean
  regeneratePending: boolean
  startPending: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Multi-factor authentication</CardTitle>
        <CardDescription>Pair phishing-resistant factors with backup codes.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {recommendations.length ? (
          <Alert>
            <AlertCircle className="h-4 w-4" />
            <AlertTitle>Recommendations</AlertTitle>
            <AlertDescription>
              <ul className="list-disc pl-4 space-y-1 text-sm">
                {recommendations.map((item, index) => (
                  <li key={`${item.type}-${index}`}>{item.reason}</li>
                ))}
              </ul>
            </AlertDescription>
          </Alert>
        ) : null}
        <div className="space-y-3">
          {factors.length === 0 ? (
            <p className="text-sm text-muted-foreground">No MFA factors enrolled yet. Start with an authenticator app.</p>
          ) : factors.map((factor) => (
            <div key={factor.id} className="rounded border p-3 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{MFA_TYPE_LABELS[factor.type]}</Badge>
                <span className="font-medium">{factor.label}</span>
                {factor.enabled ? <Badge variant="secondary">Active</Badge> : <Badge variant="destructive">Disabled</Badge>}
                <span className="text-xs text-muted-foreground ml-auto">Last used {relativeTime(factor.lastUsedAt)}</span>
              </div>
              {factor.type !== 'backup_codes' ? (
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => onDisableFactor(factor)}
                    disabled={disablePending}
                  >
                    Disable
                  </Button>
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
                  <span>{factor.remainingCodes ?? 0} codes remaining</span>
                  <Button type="button" variant="outline" size="sm" onClick={onRegenerateCodes} disabled={regeneratePending}>
                    {regeneratePending ? 'Regenerating…' : 'Regenerate codes'}
                  </Button>
                </div>
              )}
              {factor.devices?.length ? (
                <div className="rounded bg-muted/50 p-2 text-xs text-muted-foreground">
                  Linked keys: {factor.devices.map((device) => device.label).join(', ')}
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </CardContent>
      <CardFooter className="flex flex-wrap gap-3">
        <Button type="button" onClick={onStartTotp} disabled={startPending}>
          {startPending ? 'Preparing…' : 'Add authenticator app'}
        </Button>
        <Button type="button" variant="outline" onClick={onRegenerateCodes} disabled={regeneratePending}>
          <RefreshCcw className="mr-2 h-4 w-4" />
          Backup codes
        </Button>
      </CardFooter>
    </Card>
  )
}

function SessionsCard({
  summary,
  sessions,
  onRevoke,
  onRevokeAll,
  onTrustToggle,
  sessionAction,
}: {
  summary: AccountSecuritySnapshot['sessions']['summary']
  sessions: SecuritySession[]
  onRevoke: (sessionId: string) => void
  onRevokeAll: () => void
  onTrustToggle: (session: SecuritySession) => void
  sessionAction: string | null
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Devices &amp; active sessions</CardTitle>
        <CardDescription>Revoke unrecognized sessions and keep a trusted device roster.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 md:grid-cols-4">
          <SessionStat icon={<Smartphone className="h-4 w-4" />} label="Active" value={summary.activeCount} />
          <SessionStat icon={<CheckCircle2 className="h-4 w-4" />} label="Trusted" value={summary.trustedCount} />
          <SessionStat icon={<RefreshCcw className="h-4 w-4" />} label="Last rotation" value={relativeTime(summary.lastRotationAt)} />
          <SessionStat icon={<AlertTriangle className="h-4 w-4" />} label="Last untrusted" value={relativeTime(summary.lastUntrustedAt)} />
        </div>
        <div className="rounded border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Device</TableHead>
                <TableHead>Location</TableHead>
                <TableHead>Last active</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">
                    No sessions found.
                  </TableCell>
                </TableRow>
              ) : sessions.map((session) => (
                <TableRow key={session.id} data-state={session.current ? 'selected' : undefined}>
                  <TableCell>
                    <div className="font-medium">{buildDeviceLabel(session)}</div>
                    <div className="text-xs text-muted-foreground">{session.platform || 'Unknown OS'}</div>
                  </TableCell>
                  <TableCell>
                    <div>{formatSessionLocation(session)}</div>
                    <div className="text-xs text-muted-foreground">IP {session.ipAddress || '—'}</div>
                  </TableCell>
                  <TableCell>{relativeTime(session.lastActiveAt)}</TableCell>
                  <TableCell>
                    <Badge variant={session.trusted ? 'secondary' : 'outline'}>{session.trusted ? 'Trusted' : 'Untrusted'}</Badge>
                  </TableCell>
                  <TableCell className="text-right space-x-2">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      onClick={() => onTrustToggle(session)}
                      disabled={sessionAction === session.id}
                    >
                      {session.trusted ? 'Untrust' : 'Trust'}
                    </Button>
                    {!session.current ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={() => onRevoke(session.id)}
                        disabled={sessionAction === session.id}
                      >
                        Revoke
                      </Button>
                    ) : (
                      <Badge variant="outline">This device</Badge>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </CardContent>
      <CardFooter className="flex flex-wrap gap-3">
        <Button type="button" variant="outline" onClick={onRevokeAll} disabled={sessionAction === '*'}>
          <LogOut className="mr-2 h-4 w-4" /> Sign out other sessions
        </Button>
      </CardFooter>
    </Card>
  )
}

function SessionStat({ icon, label, value }: { icon: ReactNode; label: string; value: ReactNode }) {
  return (
    <div className="rounded border bg-muted/40 p-3">
      <div className="flex items-center gap-2 text-xs uppercase tracking-wide text-muted-foreground">
        {icon}
        {label}
      </div>
      <div className="text-lg font-semibold">{value}</div>
    </div>
  )
}

function RecoveryCard({
  recovery,
  onChannelChange,
  onSave,
  saving,
  onRegenerateCodes,
  regeneratePending,
}: {
  recovery: SecurityRecoverySettings
  onChannelChange: (key: 'primaryEmail' | 'backupEmail' | 'sms', value: string) => void
  onSave: () => void
  saving: boolean
  onRegenerateCodes: () => void
  regeneratePending: boolean
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recovery &amp; break glass</CardTitle>
        <CardDescription>Keep recovery channels verified before enabling stricter lockouts.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div className="space-y-3">
          <Label htmlFor="recovery-primary">Primary email</Label>
          <Input
            id="recovery-primary"
            value={recovery.primaryEmail.value}
            onChange={(event) => onChannelChange('primaryEmail', event.target.value)}
            placeholder="you@example.com"
          />
          <Label htmlFor="recovery-backup">Backup email</Label>
          <Input
            id="recovery-backup"
            value={recovery.backupEmail?.value ?? ''}
            onChange={(event) => onChannelChange('backupEmail', event.target.value)}
            placeholder="Add a secondary address"
          />
          <Label htmlFor="recovery-sms">Recovery SMS</Label>
          <Input
            id="recovery-sms"
            value={recovery.sms?.value ?? ''}
            onChange={(event) => onChannelChange('sms', event.target.value)}
            placeholder="+1 (555) 123-4567"
          />
        </div>
        <div className="rounded bg-muted/50 p-3">
          <div className="text-xs uppercase tracking-wide text-muted-foreground">Break-glass contacts</div>
          {recovery.contacts.length === 0 ? (
            <p className="text-sm text-muted-foreground">No standby approvers configured.</p>
          ) : (
            <ul className="mt-2 space-y-2">
              {recovery.contacts.map((contact) => (
                <li key={contact.id} className="flex flex-col">
                  <span className="font-medium">{contact.name}</span>
                  <span className="text-xs text-muted-foreground">{contact.email} {contact.phone ? `• ${contact.phone}` : ''}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
      <CardFooter className="flex flex-wrap gap-3">
        <Button type="button" onClick={onSave} disabled={saving}>
          {saving ? 'Saving…' : 'Save recovery contacts'}
        </Button>
        <Button type="button" variant="outline" onClick={onRegenerateCodes} disabled={regeneratePending}>
          <KeyRound className="mr-2 h-4 w-4" />
          Backup codes
        </Button>
        <div className="text-xs text-muted-foreground ml-auto">{recovery.backupCodesRemaining} codes remaining • last generated {relativeTime(recovery.lastCodesGeneratedAt)}</div>
      </CardFooter>
    </Card>
  )
}

function AlertsPointerCard({ alerts }: { alerts: SecurityAlertSettings }) {
  const enabledPreferences = alerts.preferences.filter((pref) => pref.enabled)
  const preview = enabledPreferences.slice(0, 3)
  const defaultChannels = formatChannelList(alerts.defaultChannels)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BellRing className="h-4 w-4 text-primary" />
          Security alerts moved
        </CardTitle>
        <CardDescription>Manage channel overrides from the Notifications workspace.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <Alert variant="secondary">
          <AlertTitle>Heads up</AlertTitle>
          <AlertDescription>Alert delivery now shares the NotificationService pipeline. Update digests, quiet hours, and critical routes under Account → Notifications.</AlertDescription>
        </Alert>
        <div className="rounded border bg-muted/40 p-3">
          <div className="text-xs uppercase tracking-wide text-muted-foreground mb-1">Default channels</div>
          <p className="font-medium">{defaultChannels}</p>
        </div>
        {preview.length ? (
          <div className="space-y-2">
            {preview.map((pref) => (
              <div key={pref.event} className="rounded border p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium">{pref.label}</span>
                  <Badge variant="outline">{pref.channels.length ? `${pref.channels.length} channel${pref.channels.length > 1 ? 's' : ''}` : 'Muted'}</Badge>
                </div>
                <div className="mt-2 flex flex-wrap gap-2 text-xs text-muted-foreground">
                  {pref.channels.length ? (
                    pref.channels.map((channel) => (
                      <Badge key={`${pref.event}-${channel}`} variant="secondary" className="bg-muted text-foreground">
                        {CHANNEL_LABELS[channel] ?? channel.toUpperCase()}
                      </Badge>
                    ))
                  ) : (
                    <span>No channels selected</span>
                  )}
                </div>
              </div>
            ))}
            {alerts.preferences.length > preview.length ? (
              <p className="text-xs text-muted-foreground">
                +{alerts.preferences.length - preview.length} more preferences are configured in Notifications.
              </p>
            ) : null}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">No alert preferences enabled yet.</p>
        )}
      </CardContent>
      <CardFooter className="flex flex-wrap gap-3">
        <Button asChild>
          <Link to="/settings/account/notifications">Manage notifications</Link>
        </Button>
        <Button asChild variant="outline">
          <Link to="/settings/account/notifications#topics">Review alert delivery</Link>
        </Button>
      </CardFooter>
    </Card>
  )
}

function formatChannelList(channels: SecurityAlertChannel[]) {
  return channels.length
    ? channels.map((channel) => CHANNEL_LABELS[channel] ?? channel.toUpperCase()).join(', ')
    : 'No defaults configured'
}

function EventsCard({ events }: { events: SecurityEventEntry[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent security events</CardTitle>
        <CardDescription>Authentication highlights synced from the audit pipeline.</CardDescription>
      </CardHeader>
      <CardContent>
        {events.length === 0 ? (
          <p className="text-sm text-muted-foreground">No events logged yet.</p>
        ) : (
          <ul className="space-y-3 text-sm">
            {events.map((event) => (
              <li key={event.id} className="rounded border p-3">
                <div className="flex items-center gap-2">
                  <Badge variant={SEVERITY_VARIANT[event.severity]}>{event.action}</Badge>
                  <span className="font-medium">{event.description}</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1 flex flex-wrap gap-3">
                  <span>{absoluteTime(event.createdAt)}</span>
                  {event.location ? (
                    <span className="flex items-center gap-1"><Wifi className="h-3 w-3" /> {event.location}</span>
                  ) : null}
                  {event.metadata && typeof event.metadata === 'object' ? (
                    <span>{JSON.stringify(event.metadata)}</span>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function TotpDialog({
  open,
  prompt,
  code,
  submitting,
  onCodeChange,
  onOpenChange,
  onSubmit,
}: {
  open: boolean
  prompt: SecurityMfaEnrollmentPrompt | null
  code: string
  submitting: boolean
  onCodeChange: (value: string) => void
  onOpenChange: (open: boolean) => void
  onSubmit: (event: React.FormEvent<HTMLFormElement>) => void
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Scan the QR code</DialogTitle>
          <DialogDescription>Scan with your authenticator app, then enter the 6-digit code.</DialogDescription>
        </DialogHeader>
        {prompt?.qrCodeDataUrl ? (
          <div className="flex justify-center">
            <img src={prompt.qrCodeDataUrl} alt="Authenticator QR code" className="h-40 w-40 border rounded" />
          </div>
        ) : null}
        {prompt?.secret ? (
          <p className="text-center text-xs text-muted-foreground">Manual entry: {prompt.secret}</p>
        ) : null}
        <form className="space-y-3" onSubmit={onSubmit}>
          <Label htmlFor="totp-code">Verification code</Label>
          <Input
            id="totp-code"
            value={code}
            onChange={(event) => onCodeChange(event.target.value)}
            placeholder="123456"
            inputMode="numeric"
          />
          <DialogFooter>
            <Button type="submit" disabled={submitting || !code.trim()}>
              {submitting ? 'Confirming…' : 'Confirm enrollment'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function BackupCodesDialog({ modal, onOpenChange }: { modal: CodesModalState; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog open={modal.open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Backup codes</DialogTitle>
          <DialogDescription>Store these one-time codes in a secure password manager.</DialogDescription>
        </DialogHeader>
        {modal.codes.length === 0 ? (
          <p className="text-sm text-muted-foreground">No codes available.</p>
        ) : (
          <div className="grid grid-cols-2 gap-2 font-mono text-sm">
            {modal.codes.map((code) => (
              <span key={code} className="rounded border px-2 py-1">{code}</span>
            ))}
          </div>
        )}
        <p className="text-xs text-muted-foreground">Expires {relativeTime(modal.expiresAt)}</p>
      </DialogContent>
    </Dialog>
  )
}

function SecurityPageSkeleton() {
  return (
    <div className="space-y-6">
      <Skeleton className="h-10 w-72" />
      <Skeleton className="h-40 w-full" />
      <div className="grid gap-6 lg:grid-cols-[2fr,1fr]">
        <Skeleton className="h-[32rem] w-full" />
        <Skeleton className="h-[32rem] w-full" />
      </div>
    </div>
  )
}
