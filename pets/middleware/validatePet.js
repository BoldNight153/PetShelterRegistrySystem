import { z } from 'zod'

// Require `dob` going forward. `age` is deprecated but still accepted if present.
const petSchema = z.object({
  id: z.number().optional(),
  name: z.string().min(1, 'Name is required'),
  type: z.string().min(1, 'Type is required'),
  dob: z.string().refine((v) => {
    if (!v) return false
    const d = new Date(v)
    return !isNaN(d.getTime()) && d <= new Date()
  }, { message: 'Date of birth is required and must be a valid past or current date (YYYY-MM-DD)' }),
  age: z.number().int().nonnegative().optional(), // deprecated
  breed: z.string().optional(),
})

export function validatePet(req, res, next) {
  try {
    const parsed = petSchema.parse(req.body)
    req.body = parsed
    return next()
  } catch (err) {
    return res.status(400).json({ error: err.errors ? err.errors.map(e => e.message) : String(err) })
  }
}

export default validatePet
