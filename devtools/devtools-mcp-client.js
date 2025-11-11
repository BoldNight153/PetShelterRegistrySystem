#!/usr/bin/env node
// Simple Chrome DevTools Protocol (MCP) client to capture network requests/responses
// Usage:
// 1) Start Chrome with --remote-debugging-port=9222
// 2) Install dependency: npm install chrome-remote-interface
// 3) Run: node devtools/devtools-mcp-client.js

/* eslint-disable no-console */
const CDP = require('chrome-remote-interface');

async function run() {
  const port = process.env.CHROME_REMOTE_PORT ? Number(process.env.CHROME_REMOTE_PORT) : 9222;
  const targetUrl = process.env.TARGET_URL || 'http://localhost:5173';
  const client = await CDP({ port });
  const { Network, Page } = client;
  await Network.enable();
  await Page.enable();

  Network.requestWillBeSent((params) => {
    try {
      const { request } = params;
      console.log(`REQUEST ${new Date().toISOString()} ${request.method} ${request.url}`);
      if (request.headers) {
        if (request.headers.cookie) console.log('  Cookie:', request.headers.cookie);
        if (request.headers['X-CSRF-Token'] || request.headers['x-csrf-token']) console.log('  X-CSRF-Token header present');
      }
    } catch (e) {
      // ignore
    }
  });

  Network.responseReceived(async (params) => {
    try {
      const { response, requestId } = params;
      console.log(`RESPONSE ${response.status} ${response.url}`);
      if (response.headers) {
        const sc = response.headers['set-cookie'] || response.headers['Set-Cookie'];
        if (sc) console.log('  Set-Cookie:', sc);
      }
      // Try to fetch body (may fail for large/binary responses)
      try {
        const body = await Network.getResponseBody({ requestId });
        if (body && body.body) {
          const len = body.base64Encoded ? Buffer.from(body.body, 'base64').length : body.body.length;
          console.log(`  Body length: ${len}`);
        }
      } catch (e) {
        // ignore
      }
    } catch (e) {
      // ignore
    }
  });

  // Print existing cookies via Network.getAllCookies if available
  try {
    const all = await Network.getAllCookies();
    if (all && all.cookies) console.log('Initial cookies:', JSON.stringify(all.cookies, null, 2));
  } catch (e) {
    // ignore
  }

  console.log('Navigating to', targetUrl);
  await Page.navigate({ url: targetUrl });
  await Page.loadEventFired();
  console.log('Page loaded; listening for network events. Press Ctrl+C to quit.');
}

run().catch((err) => {
  console.error('MCP client error:', err);
  process.exit(1);
});
