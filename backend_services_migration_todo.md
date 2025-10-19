# Service-by-service migration

- [x] migrate-user-service: Update `backend/src/services/userService.ts` to implement existing interface; validate with unsuppressed Jest and tsc build. 🔴
- [x] ensure-container-registration: Verify `backend/src/container.ts` and `backend/src/tests/helpers/testContainer.ts` register canonical bindings and legacy aliases; adjust scopes if needed and validate tests. 🔴
- [x] migrate-owner-service: Add/verify `IOwnerService` and ensure `backend/src/services/ownerService.ts` implements it. Validate tests/build. 🔴
- [x] migrate-shelter-service: Create/verify `IShelterService` and update `backend/src/services/shelterService.ts` to implement it. Validate tests/build. 🔴
- [x] migrate-location-service: Create/verify `ILocationService` and update `backend/src/services/locationService.ts` to implement it. Validate tests/build. 🔴
- [x] migrate-medical-record-service: Add `implements IMedicalRecordService` to `backend/src/services/medicalRecordService.ts` (type-only) and validate tests/build. 🔴
- [x] run-backend-tests: Run backend tests unsuppressed to validate recent migrations and then run TypeScript build. 🔴
- [x] migrate-pet-service: Tighten `IPetService` types and ensure `backend/src/services/petService.ts` implements it. Validate tests/build. 🔴
- [x] migrate-petowner-service: Verify `backend/src/services/petOwnerService.ts` implements `IPetOwnerService` and validate with tests/build. 🟡
- [x] migrate-event-service: Add `implements IEventService` to `backend/src/services/eventService.ts` (type-only) and validate tests/build. 🟡
- [x] migrate-rate-limit-service: Tighten or create `IRateLimitService` and update `backend/src/services/rateLimitService.ts` to implement it (type-only). Validate with unsuppressed Jest and tsc build. 🔴
- [x] migrate-role-service: Ensure `RoleService` implements `IRoleService` and validate (if not already). 🟡
- [x] migrate-settings-service: Add/verify `ISettingsService` and update `backend/src/services/settingsService.ts` to implement it. Validate tests/build. 🟡
- [x] migrate-audit-service: Add/verify `IAuditService` and update `backend/src/services/auditService.ts` to implement it (type-only). Validate with unsuppressed Jest and tsc build. 🟡
- [x] migrate-auth-service: Add/verify `IAuthService` and update `backend/src/services/authService.ts` to implement it (type-only). Validate with unsuppressed Jest and tsc build. 🔴
- [x] final-interface-sweep: Search all `backend/src/services/interfaces` for remaining `any` types and tighten to Prisma or specific types where safe; validate tests/build. 🟡