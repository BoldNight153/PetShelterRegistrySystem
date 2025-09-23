# Pet Shelter Registry System

This repository contains a small Pet Shelter Registry example with a Node/Express backend and a React + Vite frontend.

## Deprecation Notice — `age` -> `dob`

We are migrating the canonical pet birth information from the numeric `age` field to an ISO date string `dob` (YYYY-MM-DD).

Why:
- `age` becomes stale over time and is not a reliable source of truth.
- Storing `dob` (date of birth) enables consistent age calculation and localization.

What changed:
- Server-side validation now requires `dob` for new and updated pets.
- API responses and request bodies include `dob` and no longer depend on `age`.
- A migration helper `pets/migrations/age-to-dob.js` is available to approximate `dob` from existing `age` values.

How to migrate local data:
1. Make sure your data is backed up.
2. Run the migration script in development to populate `dob` for seeded data:

```bash
node ./pets/migrations/run-migration.js
```

3. Once `dob` is populated and verified, remove `age` from seeds and tests (optional — this repo includes a migration run for demos).

Notes:
- `age` is currently accepted as a deprecated field for compatibility, but it will be removed after migration and client updates.
- Keep migration scripts in the repo to demonstrate the migration process for portfolio purposes.

---

If you need help performing the migration on production data or automating it, I can assist with a migration plan and scripts tailored to your environment.
