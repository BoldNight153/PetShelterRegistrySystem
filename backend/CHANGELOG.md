# Changelog

## [0.2.0](https://github.com/BoldNight153/PetShelterRegistrySystem/compare/backend-v0.1.0...backend-v0.2.0) (2025-10-16)

### Features

- Auth security: persisted account lockout (auto + manual) and password history enforcement
- Settings-driven overrides for rate limits and lockouts: `security.loginIpWindowSec`, `security.loginIpLimit`, `security.loginLockWindowSec`, `security.loginLockThreshold`, `security.loginLockDurationMin`, `security.passwordHistoryLimit` with env fallbacks
- Admin endpoints: `POST /admin/users/lock`, `POST /admin/users/unlock`, `GET/PUT /admin/settings`, roles/permissions CRUD and assignments
- Admin-only API docs gating

### Tests

- Add Jest suites for lockout, manual lock/unlock, password history, and rate limit edges; fix seed and test helpers to ensure email verification behavior

## [0.1.0](https://github.com/BoldNight153/PetShelterRegistrySystem/compare/backend-v0.0.1...backend-v0.1.0) (2025-10-05)


### Features

* **frontend:** integrate shadcn sidebar-07, add tsconfig alias and Tailwind/PostCSS fixes ([b9c488a](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/b9c488a3ccd0d0ca5fec9faab0908556f22b1490))


### Documentation

* pin ReDoc bundle to v2.5.1 and add SRI; relax CSP for docs endp… ([f8c3bd4](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/f8c3bd4a2da2f02ab40c67827281bb439cb2ed62))
* pin ReDoc bundle to v2.5.1 and add SRI; relax CSP for docs endpoint ([f6c8b7c](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/f6c8b7c7a418e99cdb5e162085c1cac599afbe0e))
