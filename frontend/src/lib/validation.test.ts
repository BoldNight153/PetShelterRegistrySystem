import { describe, it, expect } from 'vitest'
import { passwordChangeSchema, passwordSchema, registerSchema } from './validation'

describe('passwordSchema', () => {
  it('accepts a strong password', () => {
    const result = passwordSchema.safeParse('Admin123!@#')
    expect(result.success).toBe(true)
  })

  it('rejects when missing requirements', () => {
    const bad = passwordSchema.safeParse('password') // no upper, digit, special
    expect(bad.success).toBe(false)
    if (!bad.success) {
      const issues = bad.error.issues.map(i => i.message)
      expect(issues).toContain('One uppercase letter')
      expect(issues).toContain('One number')
      expect(issues).toContain('One special character')
    }
  })
})

describe('registerSchema', () => {
  it('requires matching confirm password', () => {
    const res = registerSchema.safeParse({
      name: 'Alice',
      email: 'alice@example.com',
      password: 'Admin123!@#',
      confirm: 'wrong',
    })
    expect(res.success).toBe(false)
    if (!res.success) {
      expect(res.error.issues.some(i => i.path.join('.') === 'confirm' && i.message.includes('Passwords do not match'))).toBe(true)
    }
  })

  it('accepts valid input', () => {
    const res = registerSchema.safeParse({
      name: 'Alice',
      email: 'alice@example.com',
      password: 'Admin123!@#',
      confirm: 'Admin123!@#',
    })
    expect(res.success).toBe(true)
  })
})

describe('passwordChangeSchema', () => {
  it('requires the current password', () => {
    const res = passwordChangeSchema.safeParse({
      currentPassword: '',
      newPassword: 'Admin123!@#',
      confirmPassword: 'Admin123!@#',
    })
    expect(res.success).toBe(false)
    if (!res.success) {
      expect(res.error.issues.some(issue => issue.path.join('.') === 'currentPassword')).toBe(true)
    }
  })

  it('enforces password requirements and matching confirmation', () => {
    const weak = passwordChangeSchema.safeParse({
      currentPassword: 'oldpassword',
      newPassword: 'short',
      confirmPassword: 'short',
    })
    expect(weak.success).toBe(false)

    const mismatch = passwordChangeSchema.safeParse({
      currentPassword: 'oldpassword',
      newPassword: 'Admin123!@#',
      confirmPassword: 'Mismatch123!@#',
    })
    expect(mismatch.success).toBe(false)
    if (!mismatch.success) {
      expect(mismatch.error.issues.some(issue => issue.path.join('.') === 'confirmPassword')).toBe(true)
    }
  })

  it('accepts valid input', () => {
    const res = passwordChangeSchema.safeParse({
      currentPassword: 'OldPassword123!@#',
      newPassword: 'NewPassword123!@#',
      confirmPassword: 'NewPassword123!@#',
    })
    expect(res.success).toBe(true)
  })
})
