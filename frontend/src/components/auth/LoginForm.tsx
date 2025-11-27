import { useCallback, useEffect, useState } from "react";
import { useAppDispatch, useAppSelector } from '@/store/hooks'
import { login as loginThunk, verifyMfaChallenge, clearPendingChallenge, selectPendingMfaChallenge } from '@/store/slices/authSlice'
import { Link } from "react-router-dom";
import PasswordInput from "@/components/ui/password-input";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { loginSchema, type LoginValues } from "@/lib/validation";
import { toast } from "sonner";
import { buildDeviceMetadata } from '@/lib/device'
import { isLoginChallengeResponse, type LoginChallengePayload } from '@/types/auth'
import MfaChallengeDialog, { type ChallengeSubmission } from '@/components/auth/MfaChallengeDialog'
import { ShieldAlert, Smartphone } from 'lucide-react'

type ErrorPayload = Record<string, unknown>

function getErrorPayload(err: unknown): ErrorPayload | null {
  if (!err || typeof err !== 'object') return null
  const candidate = err as Record<string, unknown>
  const payload = candidate.payload ?? candidate.data ?? null
  if (payload && typeof payload === 'object') {
    return payload as ErrorPayload
  }
  return null
}

function formatUntil(value: unknown): string | null {
  if (!value) return null
  const asDate = value instanceof Date ? value : new Date(value as any)
  if (!Number.isNaN(asDate.getTime())) {
    return `Locked until ${asDate.toLocaleString()}`
  }
  if (typeof value === 'string' && value.trim()) {
    return value.trim()
  }
  return null
}

function extractErrorDetails(err: unknown): string[] {
  const payload = getErrorPayload(err)
  if (!payload) return []
  const details: string[] = []
  const reason = payload.reason
  if (typeof reason === 'string' && reason.trim()) {
    details.push(`Reason: ${reason.trim()}`)
  }
  const untilMsg = formatUntil(payload.until)
  if (untilMsg) details.push(untilMsg)
  const hint = payload.hint
  if (typeof hint === 'string' && hint.trim()) details.push(hint.trim())
  const suggestion = payload.suggestion
  if (typeof suggestion === 'string' && suggestion.trim()) details.push(suggestion.trim())
  const nestedError = payload.error
  if (nestedError && typeof nestedError === 'object') {
    const nestedMessage = (nestedError as Record<string, unknown>).message
    if (typeof nestedMessage === 'string' && nestedMessage.trim()) {
      details.push(nestedMessage.trim())
    }
  }
  const flattened = payload.details
  if (flattened && typeof flattened === 'object') {
    const formErrors = (flattened as Record<string, unknown>).formErrors
    if (Array.isArray(formErrors)) {
      for (const msg of formErrors) {
        if (typeof msg === 'string' && msg.trim()) details.push(msg.trim())
      }
    }
    const fieldErrors = (flattened as Record<string, unknown>).fieldErrors
    if (fieldErrors && typeof fieldErrors === 'object') {
      for (const [field, messages] of Object.entries(fieldErrors)) {
        if (Array.isArray(messages)) {
          messages.forEach((msg) => {
            if (typeof msg === 'string' && msg.trim()) {
              details.push(`${field}: ${msg.trim()}`)
            }
          })
        }
      }
    }
  }
  return Array.from(new Set(details))
}

type LoginFormProps = {
  onSuccess?: () => void;
  switchToRegister?: () => void;
};

export function LoginForm({ onSuccess, switchToRegister }: LoginFormProps) {
  const dispatch = useAppDispatch()
  const pendingChallenge = useAppSelector(selectPendingMfaChallenge)
  const [error, setError] = useState<string | null>(null)
  const [errorDetails, setErrorDetails] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [trustThisDevice, setTrustThisDevice] = useState(false)
  const [challenge, setChallenge] = useState<LoginChallengePayload | null>(pendingChallenge ?? null)
  const [challengeError, setChallengeError] = useState<string | null>(null)
  const [challengeErrorDetails, setChallengeErrorDetails] = useState<string[]>([])
  const [verifyingChallenge, setVerifyingChallenge] = useState(false)

  useEffect(() => {
    setChallenge(pendingChallenge ?? null)
    if (!pendingChallenge) {
      setChallengeError(null)
      setChallengeErrorDetails([])
    }
  }, [pendingChallenge])

  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
    mode: "onBlur",
  })

  const handleLogin = form.handleSubmit(async (vals) => {
    setLoading(true)
    setError(null)
    setErrorDetails([])
    setChallengeError(null)
    setChallengeErrorDetails([])
    try {
      const deviceMetadata = await buildDeviceMetadata()
      const result = await dispatch(loginThunk({
        email: vals.email,
        password: vals.password,
        trustThisDevice,
        ...deviceMetadata,
      })).unwrap()

      if (isLoginChallengeResponse(result)) {
        setChallenge(result.challenge)
        toast.message('Additional verification required', {
          description: 'Enter a code from your trusted factor to finish signing in.',
        })
        return
      }

      toast.success("Signed in successfully")
      onSuccess?.()
    } catch (err) {
      const msg = err instanceof Error && err.message ? err.message : 'Login failed'
      setError(msg)
      setErrorDetails(extractErrorDetails(err))
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  })

  const handleChallengeSubmit = useCallback(async (payload: ChallengeSubmission) => {
    if (!challenge) return
    setVerifyingChallenge(true)
    setChallengeError(null)
    setChallengeErrorDetails([])
    try {
      const deviceMetadata = await buildDeviceMetadata()
      const { trustThisDevice: payloadTrust, ...rest } = payload
      await dispatch(verifyMfaChallenge({
        challengeId: challenge.id,
        ...rest,
        trustThisDevice: typeof payloadTrust === 'boolean' ? payloadTrust : trustThisDevice,
        ...deviceMetadata,
      })).unwrap()
      toast.success('Verification successful')
      setChallenge(null)
      setChallengeErrorDetails([])
      onSuccess?.()
    } catch (err) {
      const msg = err instanceof Error && err.message ? err.message : 'Verification failed'
      setChallengeError(msg)
      setChallengeErrorDetails(extractErrorDetails(err))
      toast.error(msg)
    } finally {
      setVerifyingChallenge(false)
    }
  }, [challenge, dispatch, onSuccess, trustThisDevice])

  const handleChallengeDismiss = useCallback(() => {
    setChallenge(null)
    setChallengeError(null)
    setChallengeErrorDetails([])
    dispatch(clearPendingChallenge())
  }, [dispatch])

  const handleChallengeExpired = useCallback(() => {
    if (!challenge) return
    setChallenge(null)
    setChallengeError('Challenge expired')
    setChallengeErrorDetails([])
    dispatch(clearPendingChallenge())
    toast.error('The MFA prompt expired. Please sign in again.')
  }, [challenge, dispatch])

  const primaryFactors = challenge?.factors.filter((factor) => factor.type !== 'backup_codes') ?? []
  const backupCodesEnabled = Boolean(challenge?.factors.some((factor) => factor.type === 'backup_codes'))

  const challengeTitle = challenge?.reason === 'untrusted_device'
    ? 'We need to make sure this is really you'
    : 'Finish signing in with MFA'

  const challengeCopy = challenge?.reason === 'untrusted_device'
    ? 'This device has not been trusted yet. Complete one of your protected factors below to trust it or continue without trusting.'
    : 'Your account requires multi-factor authentication. Use one of your enrolled factors to finish signing in.'

  return (
    <>
      <Form {...form}>
        <form onSubmit={handleLogin} className="max-w-sm space-y-3">
        {challenge ? (
          <Alert className="space-y-2">
            <AlertTitle className="flex items-center gap-2 text-base"><ShieldAlert className="h-4 w-4" />{challengeTitle}</AlertTitle>
            <AlertDescription className="space-y-2 text-sm">
              <p>{challengeCopy}</p>
              <div className="flex flex-wrap gap-2">
                {primaryFactors.map((factor) => (
                  <Badge key={factor.id} variant={factor.id === challenge.defaultFactorId ? 'default' : 'outline'}>
                    {factor.label || factor.type.replace('_', ' ')}
                  </Badge>
                ))}
                {backupCodesEnabled ? <Badge variant="secondary">Backup codes</Badge> : null}
              </div>
              {challenge.device ? (
                <p className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Smartphone className="h-3.5 w-3.5" />
                  {challenge.device.label || 'This browser'} • {challenge.device.platform || 'Unknown platform'}
                </p>
              ) : null}
            </AlertDescription>
          </Alert>
        ) : null}
        <FormField
          control={form.control}
          name="email"
          render={({ field, fieldState }) => (
            <FormItem>
              <FormLabel>Email</FormLabel>
              <FormControl>
                <Input
                  type="email"
                  placeholder="you@example.com"
                  {...field}
                  className={fieldState.error ? "border-destructive ring-1 ring-destructive" : (fieldState.isTouched && field.value ? "ring-1 ring-success" : "")}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="password"
          render={({ field, fieldState }) => (
            <FormItem>
              <FormLabel>Password</FormLabel>
              <FormControl>
                <PasswordInput
                  {...field}
                  className={fieldState.error ? "border-destructive ring-1 ring-destructive" : (fieldState.isTouched && field.value ? "ring-1 ring-success" : "")}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
          <div className="rounded border border-dashed p-3">
            <div className="flex items-start gap-3">
              <Checkbox
                id="trust-device"
                checked={trustThisDevice}
                onCheckedChange={(checked) => setTrustThisDevice(Boolean(checked))}
                disabled={loading}
              />
              <div>
                <Label htmlFor="trust-device" className="text-sm font-medium">
                  Trust this device
                </Label>
                <p className="text-xs text-muted-foreground">
                  Skip MFA challenges on this browser unless we detect a risk signal.
                </p>
              </div>
            </div>
          </div>
            {error ? (
              <Alert variant="destructive">
                <AlertTitle>Sign-in failed</AlertTitle>
                <AlertDescription className="space-y-2 text-sm">
                  <p>{error}</p>
                  {errorDetails.length ? (
                    <ul className="list-disc space-y-1 pl-5 text-xs">
                      {errorDetails.map((detail) => (
                        <li key={detail}>{detail}</li>
                      ))}
                    </ul>
                  ) : null}
                </AlertDescription>
              </Alert>
            ) : null}
          <Button type="submit" disabled={loading} className="w-full">
            {loading ? "Signing in…" : "Sign in"}
          </Button>
        <p className="text-xs text-muted-foreground">
          Don’t have an account? {switchToRegister ? (
            <button type="button" className="underline" onClick={switchToRegister}>
              Create one
            </button>
          ) : (
            <Link to="/register" className="underline">Create one</Link>
          )}
        </p>
        </form>
      </Form>
      <MfaChallengeDialog
        open={Boolean(challenge)}
        challenge={challenge}
        verifying={verifyingChallenge}
        error={challengeError}
        errorDetails={challengeErrorDetails}
        onSubmit={handleChallengeSubmit}
        onCancel={handleChallengeDismiss}
        onExpired={handleChallengeExpired}
      />
    </>
  );
}

export default LoginForm;
