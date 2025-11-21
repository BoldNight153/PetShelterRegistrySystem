import { useEffect, useMemo, useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { RadioGroup, RadioGroupItem } from '@/components/ui/radio-group'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { LoginChallengePayload, LoginChallengeFactor } from '@/types/auth'
import { Clock, ShieldAlert, Smartphone } from 'lucide-react'

export type ChallengeSubmission = {
  method: 'totp' | 'backup_code'
  code?: string
  backupCode?: string
  factorId?: string
  trustThisDevice?: boolean
}

type Props = {
  challenge: LoginChallengePayload | null
  open: boolean
  verifying: boolean
  error?: string | null
  onSubmit: (input: ChallengeSubmission) => Promise<void> | void
  onCancel: () => void
  onExpired: () => void
}

const FACTOR_LABELS: Record<LoginChallengeFactor['type'], string> = {
  totp: 'Authenticator app',
  sms: 'SMS code',
  push: 'Push notification',
  hardware_key: 'Security key',
  backup_codes: 'Backup codes',
}

function formatRelative(ms: number): string {
  const totalSeconds = Math.max(0, Math.ceil(ms / 1000))
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes}:${seconds.toString().padStart(2, '0')}`
}

export function MfaChallengeDialog({ challenge, open, verifying, error, onSubmit, onCancel, onExpired }: Props) {
  const [mode, setMode] = useState<'totp' | 'backup_code'>('totp')
  const [selectedFactor, setSelectedFactor] = useState<string>('')
  const [code, setCode] = useState('')
  const [backupCode, setBackupCode] = useState('')
  const [trustDevice, setTrustDevice] = useState<boolean>(false)
  const [remainingMs, setRemainingMs] = useState<number>(0)

  const factors = useMemo(() => challenge?.factors ?? [], [challenge])
  const primaryFactors = useMemo(() => factors.filter((factor) => factor.type !== 'backup_codes'), [factors])
  const hasBackupCodes = useMemo(() => factors.some((factor) => factor.type === 'backup_codes'), [factors])

  useEffect(() => {
    if (!challenge) return
    const preferred = challenge.defaultFactorId ?? primaryFactors[0]?.id ?? ''
    setSelectedFactor(preferred)
    setMode(primaryFactors.length ? 'totp' : 'backup_code')
    setTrustDevice(Boolean(challenge.device?.trustRequested))
    setCode('')
    setBackupCode('')
    const tick = () => {
      const diff = new Date(challenge.expiresAt).getTime() - Date.now()
      setRemainingMs(Math.max(0, diff))
    }
    tick()
    const interval = window.setInterval(tick, 1000)
    return () => { window.clearInterval(interval) }
  }, [challenge, primaryFactors])

  useEffect(() => {
    if (!challenge) return
    if (remainingMs > 0) return
    onExpired()
  }, [challenge, remainingMs, onExpired])

  if (!challenge) {
    return null
  }

  const allowFactorTab = primaryFactors.length > 0
  const allowBackupTab = hasBackupCodes
  const disableSubmit = verifying || (mode === 'totp' ? !code.trim() : !backupCode.trim())

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const payload: ChallengeSubmission = mode === 'backup_code'
      ? { method: 'backup_code', backupCode: backupCode.trim(), trustThisDevice: trustDevice }
      : {
          method: 'totp',
          code: code.trim(),
          factorId: selectedFactor || challenge.defaultFactorId || undefined,
          trustThisDevice: trustDevice,
        }
    await onSubmit(payload)
  }

  const reasonLabel = challenge.reason === 'untrusted_device' ? 'Untrusted device' : 'MFA required'
  const expiresIn = formatRelative(remainingMs)

  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next) onCancel() }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Verify it&apos;s really you</DialogTitle>
          <DialogDescription>
            Complete the requested factor to finish signing in. Sessions stay paused until verification succeeds.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Badge variant="secondary">{reasonLabel}</Badge>
            <Clock className="h-4 w-4" />
            <span>Expires in {expiresIn}</span>
          </div>

          {(allowFactorTab || allowBackupTab) ? (
            <Tabs value={mode} onValueChange={(value) => setMode(value as 'totp' | 'backup_code')}>
              <TabsList className="grid grid-cols-2">
                {allowFactorTab ? <TabsTrigger value="totp">Authenticator</TabsTrigger> : null}
                {allowBackupTab ? <TabsTrigger value="backup_code">Backup code</TabsTrigger> : null}
              </TabsList>
              {allowFactorTab ? (
                <TabsContent value="totp" className="space-y-3">
                  <Label>Choose a factor</Label>
                  <RadioGroup value={selectedFactor} onValueChange={setSelectedFactor} className="space-y-2">
                    {primaryFactors.map((factor) => (
                      <Label key={factor.id} className="flex cursor-pointer items-start gap-3 rounded border p-3 text-sm">
                        <RadioGroupItem value={factor.id} className="mt-1" />
                        <div>
                          <div className="font-medium">{factor.label || FACTOR_LABELS[factor.type]}</div>
                          <p className="text-xs text-muted-foreground">{FACTOR_LABELS[factor.type]}</p>
                        </div>
                      </Label>
                    ))}
                  </RadioGroup>
                  <div className="space-y-2">
                    <Label htmlFor="mfa-code">Authenticator code</Label>
                    <Input
                      id="mfa-code"
                      value={code}
                      onChange={(event) => setCode(event.target.value)}
                      placeholder="123456"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      disabled={verifying}
                    />
                  </div>
                </TabsContent>
              ) : null}
              {allowBackupTab ? (
                <TabsContent value="backup_code" className="space-y-2">
                  <Label htmlFor="backup-code">Enter a backup code</Label>
                  <Input
                    id="backup-code"
                    value={backupCode}
                    onChange={(event) => setBackupCode(event.target.value)}
                    placeholder="word-word-word-word"
                    disabled={verifying}
                  />
                  <p className="text-xs text-muted-foreground">Each backup code may be used once.</p>
                </TabsContent>
              ) : null}
            </Tabs>
          ) : (
            <Alert variant="destructive">
              <ShieldAlert className="h-4 w-4" />
              <AlertTitle>No factors available</AlertTitle>
              <AlertDescription>Contact an administrator to regain access.</AlertDescription>
            </Alert>
          )}

          {challenge.device ? (
            <div className="rounded border bg-muted/40 p-3 text-sm">
              <div className="flex items-center gap-2 font-medium">
                <Smartphone className="h-4 w-4" />
                Device insight
              </div>
              <p className="text-muted-foreground">
                {challenge.device.label || 'This browser'} • {challenge.device.platform || 'Unknown platform'}
              </p>
            </div>
          ) : null}

          {challenge.device.allowTrust ? (
            <div className="flex items-start gap-3 rounded border border-dashed p-3">
              <Checkbox
                id="trust-mfa-device"
                checked={trustDevice}
                onCheckedChange={(checked) => setTrustDevice(Boolean(checked))}
                disabled={verifying}
              />
              <div className="space-y-1">
                <Label htmlFor="trust-mfa-device" className="text-sm font-medium">Trust this device</Label>
                <p className="text-xs text-muted-foreground">Skip MFA on this browser unless we detect risky changes.</p>
              </div>
            </div>
          ) : null}

          {error ? (
            <Alert variant="destructive">
              <AlertTitle>Verification failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}

          <DialogFooter className="flex flex-col gap-2 sm:flex-row">
            <Button type="submit" disabled={disableSubmit} className="flex-1">
              {verifying ? 'Verifying…' : 'Verify sign-in'}
            </Button>
            <Button type="button" variant="outline" onClick={onCancel} className="flex-1">
              Cancel sign-in
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default MfaChallengeDialog
