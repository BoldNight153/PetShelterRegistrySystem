#!/usr/bin/env node
/* Seed runner wrapper that calls prisma/seed.js if present */
import { execSync } from 'child_process'
import fs from 'fs'

if (fs.existsSync('prisma/seed.js')) {
  console.log('Running prisma/seed.js...')
  execSync('node prisma/seed.js', { stdio: 'inherit' })
  console.log('Seed complete')
} else {
  console.log('No prisma/seed.js found — nothing to do')
}
