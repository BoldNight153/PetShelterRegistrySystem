# feat(frontend/header): Mobile-only Team Switcher in sticky header

This PR adjusts the header layout to show the Team Switcher on small/mobile viewports and hide it on larger screens. It also adds documentation updates.

## Changes
- frontend: Show Team Switcher in sticky header on mobile only (md:hidden)
- docs: Add comprehensive root README with setup, theming, ReDoc, troubleshooting
- docs: Update CHANGELOG with release notes

## Why
- Better use of limited header space on small screens while keeping desktop cleaner (sidebar provides the switcher there).

## Validation
- Frontend typecheck and production build passed locally.
- Vite proxy for /api-docs and /health works.

## Screenshots
- N/A (UI is responsive; small screens will show Team Switcher next to the sidebar trigger)

## Release
- Target tag: v0.2.1
