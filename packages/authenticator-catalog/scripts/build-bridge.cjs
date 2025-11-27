const fs = require('fs')
const path = require('path')

const distDir = path.resolve(__dirname, '..', 'dist')
const ensureDir = (dir) => { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }) }

ensureDir(distDir)

const esmBridge = [
  "export * from './esm/index.js';",
  "export { default } from './esm/index.js';",
  ''
].join('\n')

const cjsBridge = [
  "'use strict';",
  "module.exports = require('./cjs/index.js');",
  "module.exports.default = module.exports;",
  ''
].join('\n')

fs.writeFileSync(path.join(distDir, 'index.js'), esmBridge)
fs.writeFileSync(path.join(distDir, 'index.cjs'), cjsBridge)
