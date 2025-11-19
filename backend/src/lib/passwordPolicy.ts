export function meetsRegistrationPasswordRequirements(password: string): boolean {
  if (typeof password !== 'string') return false;
  return password.length >= 8
    && /[A-Z]/.test(password)
    && /[a-z]/.test(password)
    && /[0-9]/.test(password)
    && /[^A-Za-z0-9]/.test(password);
}
