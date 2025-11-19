import * as z from "zod"

export const nameSchema = z.string().min(1, "Name is required").max(100, "Name is too long")
export const emailSchema = z.string().min(1, "Email is required").email("Enter a valid email address")
export const passwordSchema = z
  .string()
  .min(8, "At least 8 characters")
  .regex(/[A-Z]/, "One uppercase letter")
  .regex(/[a-z]/, "One lowercase letter")
  .regex(/[0-9]/, "One number")
  .regex(/[^A-Za-z0-9]/, "One special character")

export const passwordChangeSchema = z
  .object({
    currentPassword: z.string().min(1, "Current password is required"),
    newPassword: passwordSchema,
    confirmPassword: z.string(),
  })
  .refine((vals) => vals.newPassword === vals.confirmPassword, {
    path: ["confirmPassword"],
    message: "Passwords do not match",
  })

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
})

export const registerSchema = z
  .object({
    name: nameSchema,
    email: emailSchema,
    password: passwordSchema,
    confirm: z.string(),
  })
  .refine((vals) => vals.password === vals.confirm, {
    path: ["confirm"],
    message: "Passwords do not match",
  })

export type LoginValues = z.infer<typeof loginSchema>
export type RegisterValues = z.infer<typeof registerSchema>
export type PasswordChangeValues = z.infer<typeof passwordChangeSchema>
