#!/usr/bin/env node
/* Lightweight migration runner for local use. This calls Prisma migrate deploy.
   Usage: node scripts/migrate.js
*/
import { execSync } from 'child_process'

try {
  console.log('Running migrations...')
  execSync('npx prisma migrate deploy', { stdio: 'inherit' })
  console.log('Migrations complete')
} catch (err) {
  console.error('Migration failed', err)
  process.exit(1)
}
