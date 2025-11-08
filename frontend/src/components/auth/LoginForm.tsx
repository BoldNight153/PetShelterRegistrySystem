import { useState } from "react";
import { useAppDispatch } from '@/store/hooks'
import { login as loginThunk } from '@/store/slices/authSlice'
import { Link } from "react-router-dom";
import PasswordInput from "@/components/ui/password-input";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Form, FormField, FormItem, FormLabel, FormControl, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { loginSchema, type LoginValues } from "@/lib/validation";
import { toast } from "sonner";

export function LoginForm({ onSuccess, switchToRegister }: { onSuccess?: () => void; switchToRegister?: () => void }) {
  // form state handled by react-hook-form
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const dispatch = useAppDispatch()

  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
    mode: "onBlur",
  });

  const onSubmit = form.handleSubmit(async (vals) => {
    setLoading(true);
    setError(null);
    try {
      await dispatch(loginThunk({ email: vals.email, password: vals.password }))
      toast.success("Signed in successfully");
      onSuccess?.();
    } catch (err: any) {
      const msg = err?.message || "Login failed";
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
        {error && <p className="text-sm text-destructive">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="inline-flex items-center rounded bg-primary text-primary-foreground px-4 py-2 disabled:opacity-50"
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>
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
  );
}

export default LoginForm;
