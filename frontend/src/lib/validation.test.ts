import { describe, it, expect } from 'vitest'
import { passwordSchema, registerSchema } from './validation'

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
