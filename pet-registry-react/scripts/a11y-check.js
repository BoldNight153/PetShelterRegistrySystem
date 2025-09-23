import puppeteer from 'puppeteer'
import fs from 'fs'
import path from 'path'
import { readFile } from 'fs/promises'
import { createRequire } from 'module'

const require = createRequire(import.meta.url)

async function scanUrl(page, url) {
  await page.goto(url, { waitUntil: 'networkidle2' })

  // inject axe
  const axePath = require.resolve('axe-core/axe.min.js')
  const axeSource = await readFile(axePath, 'utf8')
  await page.evaluate(axeSource)

  const results = await page.evaluate(async () => {
    // eslint-disable-next-line no-undef
    return await axe.run(document, {
      runOnly: {
        type: 'tag',
        values: ['wcag2a', 'wcag2aa']
      }
    })
  })

  return results
}

async function main() {
  const argv = process.argv.slice(2)
  const routesArg = argv.find(a => a.startsWith('--routes=')) || '--routes=/'
  const routes = routesArg.replace('--routes=', '').split(',').map(r => r.trim()).filter(Boolean)
  const base = (argv.find(a => a.startsWith('--base=')) || '--base=http://localhost:5173').replace('--base=', '')
  const outPath = (argv.find(a => a.startsWith('--out=')) || `--out=${path.join(process.cwd(), 'a11y-report.json')}`).replace('--out=', '')

  console.log('Scanning base:', base)
  console.log('Routes:', routes)

  const browser = await puppeteer.launch({ headless: 'new', args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  const page = await browser.newPage()

  const reports = []
  for (const route of routes) {
    const url = route.startsWith('http') ? route : `${base.replace(/\/$/, '')}/${route.replace(/^\//, '')}`
    console.log('Scanning', url)
    try {
      const result = await scanUrl(page, url)
      reports.push({ url, result })
      console.log(`  - Violations: ${result.violations.length}`)
    } catch (err) {
      console.error('  ! Error scanning', url, err && err.message ? err.message : err)
      reports.push({ url, error: String(err) })
    }
  }

  await browser.close()

  await fs.promises.writeFile(outPath, JSON.stringify({ generated: new Date().toISOString(), reports }, null, 2), 'utf8')
  console.log('Accessibility report written to', outPath)
}

main().catch(err => { console.error(err); process.exit(1) })
