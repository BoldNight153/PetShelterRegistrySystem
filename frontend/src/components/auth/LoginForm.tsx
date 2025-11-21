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
import { loginSchema, type LoginValues } from "@/lib/validation";
import { toast } from "sonner";
import { buildDeviceMetadata } from '@/lib/device'
import { isLoginChallengeResponse, type LoginChallengePayload } from '@/types/auth'
import MfaChallengeDialog, { type ChallengeSubmission } from '@/components/auth/MfaChallengeDialog'

type LoginFormProps = {
  onSuccess?: () => void;
  switchToRegister?: () => void;
};

export function LoginForm({ onSuccess, switchToRegister }: LoginFormProps) {
  const dispatch = useAppDispatch()
  const pendingChallenge = useAppSelector(selectPendingMfaChallenge)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [trustThisDevice, setTrustThisDevice] = useState(false)
  const [challenge, setChallenge] = useState<LoginChallengePayload | null>(pendingChallenge ?? null)
  const [challengeError, setChallengeError] = useState<string | null>(null)
  const [verifyingChallenge, setVerifyingChallenge] = useState(false)

  useEffect(() => {
    setChallenge(pendingChallenge ?? null)
    if (!pendingChallenge) {
      setChallengeError(null)
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
    setChallengeError(null)
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
    } catch (err: any) {
      const msg = err?.message || "Login failed"
      setError(msg)
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  })

  const handleChallengeSubmit = useCallback(async (payload: ChallengeSubmission) => {
    if (!challenge) return
    setVerifyingChallenge(true)
    setChallengeError(null)
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
      onSuccess?.()
    } catch (err: any) {
      const msg = err?.message || 'Verification failed'
      setChallengeError(msg)
      toast.error(msg)
    } finally {
      setVerifyingChallenge(false)
    }
  }, [challenge, dispatch, onSuccess, trustThisDevice])

  const handleChallengeDismiss = useCallback(() => {
    setChallenge(null)
    setChallengeError(null)
    dispatch(clearPendingChallenge())
  }, [dispatch])

  const handleChallengeExpired = useCallback(() => {
    if (!challenge) return
    setChallenge(null)
    setChallengeError('Challenge expired')
    dispatch(clearPendingChallenge())
    toast.error('The MFA prompt expired. Please sign in again.')
  }, [challenge, dispatch])

  return (
    <>
      <Form {...form}>
        <form onSubmit={handleLogin} className="max-w-sm space-y-3">
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
          {error && <p className="text-sm text-destructive">{error}</p>}
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
        onSubmit={handleChallengeSubmit}
        onCancel={handleChallengeDismiss}
        onExpired={handleChallengeExpired}
      />
    </>
  );
}

export default LoginForm;
