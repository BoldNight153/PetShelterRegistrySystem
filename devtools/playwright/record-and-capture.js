#!/usr/bin/env node
/*
 Playwright recorder script
 - Launches Chromium
 - Navigates to TARGET_URL
 - Calls GET /auth/csrf (credentials: include)
 - Calls POST /auth/login with provided ADMIN_EMAIL / ADMIN_PASSWORD
 - Reloads the page
 - Calls POST /auth/refresh
 - Logs network request/response events and cookies to devtools/playwright/logs.json

Usage:
  npm install -D playwright
  npx playwright install chromium
  node devtools/playwright/record-and-capture.js
*/

const fs = require('fs');
const path = require('path');

// Allow resolving Playwright from the frontend workspace node_modules when this
// script is executed from the repo root. Prepend frontend/node_modules to
// module.paths so `require('playwright')` works even though the script lives
// under /devtools.
const frontendNodeModules = path.resolve(__dirname, '../../frontend/node_modules');
if (fs.existsSync(frontendNodeModules)) {
  module.paths.unshift(frontendNodeModules);
}

const { chromium } = require('playwright');

const TARGET_URL = process.env.TARGET_URL || 'http://localhost:5173';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@example.com';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!@#';

const outFile = path.resolve(__dirname, 'logs.json');
const events = [];

function pushEvent(e) {
  events.push({ ts: new Date().toISOString(), ...e });
  // Append to stdout for real-time debugging
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...e }));
}

async function capture() {
  const browser = await chromium.launch({ headless: false });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Record requests and capture a snapshot of the browser cookie store at the moment
  page.on('request', async (req) => {
    try {
      const headers = req.headers();
      const cookiesSnapshot = await context.cookies();
      const r = {
        type: 'request',
        method: req.method(),
        url: req.url(),
        headers,
        postData: req.postData ? req.postData() : undefined,
        browserCookies: cookiesSnapshot,
      };
      // Keep top-level cookieHeader for convenience if present
      if (headers && headers.cookie) r.cookieHeader = headers.cookie;
      pushEvent(r);
    } catch (e) {
      // best-effort; do not crash recording
      pushEvent({ type: 'request', method: req.method(), url: req.url(), headers: req.headers(), error: 'failed to capture cookies' });
    }
  });

  // Capture page console messages so client-side debug logs are available
  // inside the recorded trace. This helps correlate client tokens with
  // network events and server logs.
  page.on('console', async (msg) => {
    try {
      const location = msg.location ? msg.location() : undefined;
      pushEvent({ type: 'console', level: msg.type(), text: msg.text(), location });
    } catch (err) {
      // non-fatal
      pushEvent({ type: 'console', level: 'error', text: 'failed to capture console message' });
    }
  });

  page.on('response', async (res) => {
    try {
      const headers = res.headers();
      const e = {
        type: 'response',
        url: res.url(),
        status: res.status(),
        headers,
      };
      if (headers['set-cookie'] || headers['Set-Cookie']) e.setCookie = headers['set-cookie'] || headers['Set-Cookie'];
      // Try to capture a small text body if available
      try {
        const ct = headers['content-type'] || '';
        if (ct.includes('application/json') || ct.includes('text/')) {
          const text = await res.text();
          e.body = text.length > 2000 ? text.slice(0, 2000) + '...TRUNCATED' : text;
        }
      } catch {
        // ignore
      }
      pushEvent(e);
    } catch (err) {
      // ignore
    }
  });

  // Go to target
  pushEvent({ type: 'info', message: `navigating to ${TARGET_URL}` });
  await page.goto(TARGET_URL, { waitUntil: 'domcontentloaded' });

  // Print initial cookies
  let c = await context.cookies();
  pushEvent({ type: 'cookies', phase: 'initial', cookies: c });

  // Step 1: GET /auth/csrf
  pushEvent({ type: 'info', message: 'GET /auth/csrf' });
  const csrf = await page.evaluate(async () => {
    const res = await fetch('/auth/csrf', { method: 'GET', credentials: 'include' });
    try { return await res.json(); } catch { return null; }
  });
  pushEvent({ type: 'csrf', value: csrf });

  // Step 2: POST /auth/login
  pushEvent({ type: 'info', message: 'POST /auth/login' });
  // Playwright page.evaluate accepts a single serializable argument. Pack
  // multiple values into an object to pass them into the page context.
  const loginResult = await page.evaluate(async (args) => {
    const { email, password, csrfToken } = args || {};
    const res = await fetch('/auth/login', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken?.csrfToken || csrfToken?.token || '' },
      body: JSON.stringify({ email, password }),
    });
    let body = null;
    try { body = await res.json(); } catch { body = await res.text().catch(() => null); }
    return { status: res.status, body };
  }, { email: ADMIN_EMAIL, password: ADMIN_PASSWORD, csrfToken: csrf });
  pushEvent({ type: 'loginResult', result: loginResult });

  // Cookies after login
  c = await context.cookies();
  pushEvent({ type: 'cookies', phase: 'afterLogin', cookies: c });

  // Reload the page
  pushEvent({ type: 'info', message: 'reloading page' });
  await page.reload({ waitUntil: 'domcontentloaded' });
  c = await context.cookies();
  pushEvent({ type: 'cookies', phase: 'afterReload', cookies: c });

  // Step 3: POST /auth/refresh
  pushEvent({ type: 'info', message: 'POST /auth/refresh' });
  const refreshResult = await page.evaluate(async (args) => {
    const { csrfToken } = args || {};
    const res = await fetch('/auth/refresh', {
      method: 'POST',
      credentials: 'include',
      headers: { 'X-CSRF-Token': csrfToken?.csrfToken || csrfToken?.token || '' },
    });
    let body = null;
    try { body = await res.json(); } catch { body = await res.text().catch(() => null); }
    return { status: res.status, body };
  }, { csrfToken: csrf });
  pushEvent({ type: 'refreshResult', result: refreshResult });

  c = await context.cookies();
  pushEvent({ type: 'cookies', phase: 'afterRefresh', cookies: c });

  // Save events
  try {
    fs.writeFileSync(outFile, JSON.stringify(events, null, 2));
    pushEvent({ type: 'info', message: `wrote ${outFile}` });
  } catch (e) {
    pushEvent({ type: 'error', message: `failed to write ${outFile}: ${String(e)}` });
  }

  // Keep browser open briefly for manual inspection
  pushEvent({ type: 'info', message: 'done; browser will remain open for 10s' });
  await new Promise((r) => setTimeout(r, 10000));
  await browser.close();
}

capture().catch((err) => {
  console.error('error:', err);
  process.exit(1);
});
