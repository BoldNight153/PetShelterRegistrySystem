#!/usr/bin/env node
/*
Helper: search for common `age` fields and remove them from JS/JSON-like files.
Produces `remove-age.patch` if changes were committed locally.
Run from repo root: `node tools/remove-age.js`
*/
import { execSync } from 'child_process'
import fs from 'fs'
import path from 'path'

function run(cmd) {
  return execSync(cmd, { encoding: 'utf8' }).trim()
}

function listGrepMatches() {
  try {
    const out = run('git grep -n --untracked --no-color "\bage\b" || true')
    return out.split('\n').filter(Boolean)
  } catch (e) {
    return []
  }
}

function removeAgeFromContent(content) {
  let out = content
  // Remove JSON-style: "age": <value>, (or with single quotes)
  out = out.replace(/\s*["']?age["']?\s*:\s*[^,\n\r]+,?/g, match => {
    // if match ends with comma, remove it; otherwise remove the whole line
    if (/,$/.test(match.trim())) return ''
    return ''
  })
  // remove simple lines like `age: 5,` in JS object literals
  out = out.replace(/^\s*age\s*:\s*[^,\n\r]+,?\s*\n/gm, '')
  return out
}

function main() {
  console.log('Scanning repository for "age" occurrences...')
  const hits = listGrepMatches()
  if (!hits.length) {
    console.log('No matches for "age" found by git grep.')
    process.exit(0)
  }

  const files = [...new Set(hits.map(line => line.split(':')[0]).filter(f => f && !f.includes('node_modules')))]
  console.log('Candidate files:', files.length)

  const changed = []
  for (const f of files) {
    if (!fs.existsSync(f)) continue
    const ext = path.extname(f).toLowerCase()
    if (!['.js', '.jsx', '.ts', '.tsx', '.json', '.md', '.html'].includes(ext)) continue
    const content = fs.readFileSync(f, 'utf8')
    if (!/\bage\b/.test(content)) continue
    const newContent = removeAgeFromContent(content)
    if (newContent !== content) {
      fs.writeFileSync(f, newContent, 'utf8')
      changed.push(f)
      console.log('Updated', f)
    }
  }

  if (!changed.length) {
    console.log('No files changed after attempting to remove `age`.')
    process.exit(0)
  }

  try {
    run('git add -A')
    // create a commit but do not push
    run('git commit -m "chore: remove deprecated age fields (automated)" || true')
    const patch = run('git format-patch -1 --stdout')
    const out = path.join(process.cwd(), 'remove-age.patch')
    fs.writeFileSync(out, patch, 'utf8')
    console.log('Wrote patch to', out)
  } catch (err) {
    console.error('Error creating patch:', err && err.message ? err.message : err)
    console.log('You can inspect `git status` and create a patch manually: `git diff > remove-age.patch`')
  }
}

main()
