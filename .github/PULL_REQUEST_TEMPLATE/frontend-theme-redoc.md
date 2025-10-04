---
name: Frontend Theme & ReDoc Improvements
about: Use this when making changes to theme synchronization and API docs
---

## Summary
Provide a concise overview of the changes related to theme handling and ReDoc.

## Why
Explain the motivation and problems addressed (e.g., flicker on navigation, low contrast, search issues).

## What changed
- Early theme initialization
- ReDoc spec loading (specUrl)
- Scoped CSS overrides for readability and dropdowns
- Event wiring and data-theme propagation

## How it works
Describe how theme precedence is applied and how ReDoc syncs with the site theme.

## Files changed
List key files touched.

## QA checklist
- [ ] Theme persists on refresh and route changes
- [ ] Docs search shows results and navigates
- [ ] Dropdowns/menus are readable in light and dark
- [ ] Code blocks and tables have sufficient contrast

## Risks and mitigations
List risks and how they are addressed.

## Screenshots / Recordings (optional)
Add before/after visuals if available.
