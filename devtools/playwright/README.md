# Playwright recorder: login + reload + refresh capture

This folder contains a small Playwright script that launches Chromium, navigates to your dev app, performs a login, reloads the page, calls `/auth/refresh`, and captures network events (request/response headers, Set-Cookie headers, and cookies). Use it to reproduce and capture the auth cookie/CSRF flow deterministically.

Prerequisites

- Node.js (>= 16)
- Install Playwright and browsers in your project root:

```bash
npm install -D playwright
npx playwright install chromium
```

Quick usage

1. Ensure your backend and frontend are running (backend on http://localhost:4000, frontend on http://localhost:5173 by default).
2. Update credentials or TARGET_URL in `record-and-capture.js` if you don't use the defaults.
3. Run the script:

```bash
node devtools/playwright/record-and-capture.js
```

By default the script will navigate to `http://localhost:5173`, request a CSRF token, POST `/auth/login` with the example admin credentials (see below), reload the page, then POST `/auth/refresh`. It prints network events and writes a `devtools/playwright/logs.json` file with captured events.

Defaults and overrides

- `TARGET_URL` environment variable to change the app URL (e.g. `http://localhost:5173`).
- `ADMIN_EMAIL` / `ADMIN_PASSWORD` to override credentials used for login.

Notes

- The script uses Playwright's page request/response events and `context.cookies()` to inspect cookie state after each step.
- If your dev environment uses a Vite proxy (as this repo does), run the dev server and backend locally as usual.
