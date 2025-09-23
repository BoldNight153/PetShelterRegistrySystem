import migrateAgeToDob from './age-to-dob.js'
import db from '../../db/db.js'

console.log('Before:', JSON.stringify(db.pets, null, 2))
const updated = migrateAgeToDob()
console.log('After:', JSON.stringify(updated, null, 2))
