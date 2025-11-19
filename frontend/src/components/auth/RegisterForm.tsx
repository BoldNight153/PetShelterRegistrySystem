import { useMemo, useState } from "react";
import { useAppDispatch } from '@/store/hooks'
import { register as registerThunk } from '@/store/slices/authSlice'
import PasswordInput from "@/components/ui/password-input";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { evaluatePasswordRules } from "@/lib/passwordRules";
import { registerSchema, type RegisterValues } from "@/lib/validation";
import { toast } from "sonner";
import { Check, X } from "lucide-react";

export function RegisterForm({ onSuccess, switchToLogin }: { onSuccess?: () => void; switchToLogin?: () => void }) {
  // form state handled by react-hook-form
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const form = useForm<RegisterValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: { name: "", email: "", password: "", confirm: "" },
    mode: "onBlur",
  })
  const dispatch = useAppDispatch()

  const pwd = form.watch("password") || ""
  const confirm = form.watch("confirm") || ""
  const rules = useMemo(() => evaluatePasswordRules(pwd), [pwd]);

  const onSubmit = form.handleSubmit(async (values) => {
    setLoading(true);
    setError(null);
    try {
  await dispatch(registerThunk({ email: values.email, password: values.password, name: values.name }))
      toast.success("Account created");
      onSuccess?.();
    } catch (err: any) {
      const msg = err?.message || "Registration failed";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  });

  return (
    <Form {...form}>
      <form onSubmit={onSubmit} className="max-w-sm space-y-3">
        <FormField
          control={form.control}
          name="name"
          render={({ field, fieldState }) => (
            <FormItem>
              <FormLabel>Name</FormLabel>
              <FormControl>
                <Input
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
        <FormField
          control={form.control}
          name="confirm"
          render={({ field, fieldState }) => (
            <FormItem>
              <FormLabel>Confirm Password</FormLabel>
              <FormControl>
                <PasswordInput
                  {...field}
                  className={fieldState.error ? "border-destructive ring-1 ring-destructive" : (fieldState.isTouched && field.value ? (pwd === field.value ? "ring-1 ring-success" : "border-destructive ring-1 ring-destructive") : "")}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <div className="text-xs text-muted-foreground">
          <p className="font-medium">Password requirements:</p>
          <ul className="mt-1 space-y-1">
            {rules.map(r => (
              <li key={r.id} className="flex items-center gap-2">
                {r.pass ? <Check className="h-4 w-4 text-success" /> : <X className="h-4 w-4 text-destructive" />}
                <span className={r.pass ? "text-success" : "text-muted-foreground"}>{r.label}</span>
              </li>
            ))}
            <li className="flex items-center gap-2">
              {pwd && confirm && pwd === confirm ? (
                <Check className="h-4 w-4 text-success" />
              ) : (
                <X className="h-4 w-4 text-destructive" />
              )}
              <span className={(pwd && confirm && pwd === confirm) ? "text-success" : "text-muted-foreground"}>
                Password and confirmation must match
              </span>
            </li>
          </ul>
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center rounded bg-primary text-primary-foreground px-4 py-2 disabled:opacity-50"
        >
          {loading ? "Creating account…" : "Create account"}
        </button>
        <p className="text-xs text-muted-foreground">
          Already have an account? {switchToLogin ? (
            <button type="button" className="underline" onClick={switchToLogin}>
              Sign in
            </button>
          ) : (
            <a href="/login" className="underline">Sign in</a>
          )}
        </p>
      </form>
    </Form>
  );
}

export default RegisterForm;
