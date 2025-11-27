# PetShelter Registry — Frontend

React 19 + Vite power the admin console for the PetShelter Registry backend. Components talk to typed service interfaces (see `src/services/interfaces/*`) so UI code never fetches data directly—it always goes through `src/lib/api.ts` via the `ServicesProvider`.

## Development workflow

1. Install dependencies once:
   ```bash
   npm install
   ```
2. Start the Vite dev server on port 5173:
   ```bash
   npm run dev
   ```
3. Run the backend (`npm run dev` from `/backend`) against the same SQLite DB so settings routes return data.
4. Keep the CI gates green before opening a PR:
   ```bash
   npm run typecheck
   npm test
   ```

## Account settings surfaces

### Account → Security (`src/pages/settings/account/security.tsx`)

- Drives password, MFA, trusted session, and recovery controls by calling the `security` service hooks (`src/services/hooks/security.ts`).
- Alert preferences are now **read-only** in this view. The card shows your current defaults plus a preview of the most important topics, then deep links into Notifications for editing so every delivery control lives in one workspace.
- MFA now reflects backend `pendingEnrollment` metadata: factor rows badge their status, destructive actions are frozen while a rotation is in progress, and the banner exposes an **Enter code to finish** action that replays the backend ticket (authenticator label, catalog tag, and expiry) so users can resume confirmation after a refresh without losing context.
- Tests live in `src/pages/settings/account/security.test.tsx` and stub the `security` service via `renderWithProviders`.

### Account → Notifications (`src/pages/settings/account/notifications.tsx`)

- Uses the `notifications` service to load/save the full notification payload—default channels, per-topic overrides, digests, quiet hours, critical escalations, and trusted devices.
- Security alert delivery moved here, so this page is the single source of truth for alert channels. Saving updates mirrors the relevant topics back into `metadata.security.alerts` for the Account → Security snapshot.
- Dedicated Vitest coverage lives in `src/pages/settings/account/notifications.test.tsx`, and normalization utilities are covered in `src/types/notifications.test.ts`.
- The **Register this device** button captures a Push API subscription (via `/notifications-sw.js`) and forwards it to `/auth/notifications/devices/register`. Provide a VAPID public key via `VITE_PUBLIC_VAPID_KEY` in your `.env` before testing push flows; without it the button will surface an error.

## Admin settings surfaces

### Admin → Authentication (`src/pages/admin/settings.tsx`)

- Admins can now manage login mode, OAuth toggles, MFA enforcement, and the authenticator catalog from a single card-based workspace. The page resolves catalog data through `useAuthenticatorCatalog`/`useAuthenticators`, so UI state always reflects the live backend list—including archived presets when an admin needs to restore them.
- Vitest coverage in `src/pages/admin/settings.test.tsx` drives the entire flow: navigation selection, security/auth saves, catalog create/edit/archive/restore interactions, and payload validation.
- The new hook tests in `src/hooks/useAuthenticatorCatalog.test.tsx` ensure the React Query plumbing calls `admin.authenticators.list` with the correct `includeArchived` flag and exposes helper lookups for downstream components.
- When iterating locally, run `npm test -- admin settings useAuthenticatorCatalog` to cover both the page and the shared hook before pushing changes. This matches the expectations enforced by the backend tests documented in `backend/README.md`.

## Testing tips

- Prefer `renderWithProviders` from `src/test-utils/renderWithProviders.tsx` when mounting pages so you get Redux, React Query, router context, and mocked services.
- Run focused suites while iterating (e.g., `npm test -- notifications security`) and finish with `npm run typecheck` + `npm test` for parity with CI.
- VS Code task **Typecheck & test both apps** mirrors the release pipeline by running backend build/tests and the frontend checks in one go.
