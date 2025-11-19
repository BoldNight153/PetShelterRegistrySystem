export type PasswordRuleState = {
  id: string
  label: string
  pass: boolean
}

export function evaluatePasswordRules(password: string | undefined | null): PasswordRuleState[] {
  const value = password ?? ''
  return [
    { id: 'len', label: 'At least 8 characters', pass: value.length >= 8 },
    { id: 'upper', label: 'One uppercase letter', pass: /[A-Z]/.test(value) },
    { id: 'lower', label: 'One lowercase letter', pass: /[a-z]/.test(value) },
    { id: 'digit', label: 'One number', pass: /[0-9]/.test(value) },
    { id: 'special', label: 'One symbol/special character', pass: /[^A-Za-z0-9]/.test(value) },
  ]
}
