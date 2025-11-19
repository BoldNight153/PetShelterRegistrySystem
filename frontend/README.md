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
- Tests live in `src/pages/settings/account/security.test.tsx` and stub the `security` service via `renderWithProviders`.

### Account → Notifications (`src/pages/settings/account/notifications.tsx`)

- Uses the `notifications` service to load/save the full notification payload—default channels, per-topic overrides, digests, quiet hours, critical escalations, and trusted devices.
- Security alert delivery moved here, so this page is the single source of truth for alert channels. Saving updates mirrors the relevant topics back into `metadata.security.alerts` for the Account → Security snapshot.
- Dedicated Vitest coverage lives in `src/pages/settings/account/notifications.test.tsx`, and normalization utilities are covered in `src/types/notifications.test.ts`.

## Testing tips

- Prefer `renderWithProviders` from `src/test-utils/renderWithProviders.tsx` when mounting pages so you get Redux, React Query, router context, and mocked services.
- Run focused suites while iterating (e.g., `npm test -- notifications security`) and finish with `npm run typecheck` + `npm test` for parity with CI.
- VS Code task **Typecheck & test both apps** mirrors the release pipeline by running backend build/tests and the frontend checks in one go.
