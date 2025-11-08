# Devtools MCP (Chrome DevTools Protocol) helper

This folder contains a small Node-based MCP (Chrome DevTools Protocol) helper to connect to a running Chrome instance (remote debugging) and log network activity (requests, responses, Set-Cookie headers and cookie state). Use this to debug cookie/CSRF/refresh flows during development.

Prerequisites

- Google Chrome (or Chromium) installed.
- Node.js available in your PATH.

Quick steps

1. Start Chrome with remote debugging enabled (macOS example):

```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --user-data-dir=/tmp/chrome-dev-profile
```

Use a separate `--user-data-dir` so it doesn't interfere with your regular profile.

2. Install the helper dependency (in project root):

```bash
npm install chrome-remote-interface --no-audit --no-fund
```

3. Run the MCP client script:

```bash
node devtools/devtools-mcp-client.js
```

You can override the port and target URL via environment variables:

- `CHROME_REMOTE_PORT` — default `9222`
- `TARGET_URL` — default `http://localhost:5173`

Notes

- The script connects to the first available target and will navigate it to `TARGET_URL` if provided. It prints request headers (including Cookie), response status and Set-Cookie headers, and attempts to fetch small response bodies for easier debugging.
- If you prefer automated headless debugging or want to script interactions, consider using Playwright or Puppeteer as an alternative.

If you run the script and paste the output here (or save to a file), I can analyze the exact request/response and cookie behavior and propose next code changes.
