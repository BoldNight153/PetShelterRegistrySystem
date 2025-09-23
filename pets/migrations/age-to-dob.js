import db from '../../db/db.js'

// This is a simple migration script that converts existing numeric `age` fields
// into an approximate `dob` (date of birth) by subtracting `age` years from today's date.
// It writes the `dob` as an ISO date string (YYYY-MM-DD). This is an approximation
// and should be validated/adjusted by domain experts if precise birthdates are needed.

function approximateDobFromAge(age) {
  if (typeof age !== 'number' || age < 0) return null
  const now = new Date()
  const dob = new Date(now.getFullYear() - age, now.getMonth(), now.getDate())
  return dob.toISOString().slice(0, 10)
}

export default function migrateAgeToDob() {
  console.log('Starting migration: age -> dob')
  db.pets = db.pets.map((pet) => {
    if ((pet.dob === undefined || pet.dob === null) && typeof pet.age === 'number') {
      return { ...pet, dob: approximateDobFromAge(pet.age) }
    }
    return pet
  })
  console.log('Migration complete')
  return db.pets
}
