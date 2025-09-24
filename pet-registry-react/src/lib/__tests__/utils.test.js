import { describe, it, expect } from 'vitest'
import { calculateAgeFromDob, formatAge } from '../utils'

describe('utils', () => {
  it('calculates age correctly', () => {
    const dob = new Date()
    dob.setFullYear(dob.getFullYear() - 2)
    dob.setMonth(dob.getMonth() - 3)
    const age = calculateAgeFromDob(dob.toISOString())
    expect(age.years).toBeGreaterThanOrEqual(1)
    expect(typeof age.months).toBe('number')
  })

  it('formats age string', () => {
    expect(formatAge({ years: 1, months: 0 })).toBe('1 year 0 months')
    expect(formatAge({ years: 2, months: 5 })).toBe('2 years 5 months')
    expect(formatAge({ years: null, months: null })).toBe('—')
  })
})
