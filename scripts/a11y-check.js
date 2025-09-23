import puppeteer from 'puppeteer'
import fs from 'fs'
import path from 'path'

import { readFile } from 'fs/promises'

async function run() {
  const browser = await puppeteer.launch({ headless: true })
  const page = await browser.newPage()
  await page.goto('http://localhost:5173')

  // inject axe
  const axePath = require.resolve('axe-core/axe.min.js')
  const axeSource = await readFile(axePath, 'utf8')
  await page.evaluate(axeSource)

  const results = await page.evaluate(async () => {
    return await axe.run()
  })

  await browser.close()

  const outPath = path.resolve(process.cwd(), 'a11y-report.json')
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2))
  console.log('Accessibility report written to', outPath)
}

run().catch(err => { console.error(err); process.exit(1) })
