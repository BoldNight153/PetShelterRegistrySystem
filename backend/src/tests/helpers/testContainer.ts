import { createContainer, asValue, asClass, asFunction } from 'awilix';
import { prismaClient } from '../../prisma/client';
import { UserService } from '../../services/userService';
import { AuthService } from '../../services/authService';
import { RateLimitService } from '../../services/rateLimitService';
import type { LimitOptions } from '../../services/rateLimitService';
import { RoleService } from '../../services/roleService';
import { SettingsService } from '../../services/settingsService';
import { AuditService } from '../../services/auditService';
import { OwnerService } from '../../services/ownerService';
import { ShelterService } from '../../services/shelterService';
import { PetService } from '../../services/petService';
import { PetOwnerService } from '../../services/petOwnerService';
import { MedicalRecordService } from '../../services/medicalRecordService';
import { LocationService } from '../../services/locationService';
import { EventService } from '../../services/eventService';

export function makeTestContainer() {
  const c = createContainer();
  c.register({
    prisma: asValue(prismaClient),
    userService: asClass(UserService).singleton(),
    authService: asClass(AuthService).singleton(),
    roleService: asClass(RoleService).singleton(),
    settingsService: asClass(SettingsService).singleton(),
    auditService: asClass(AuditService).singleton(),
    ownerService: asClass(OwnerService).singleton(),
    shelterService: asClass(ShelterService).singleton(),
    petService: asClass(PetService).singleton(),
    petOwnerService: asClass(PetOwnerService).singleton(),
    medicalRecordService: asClass(MedicalRecordService).singleton(),
    locationService: asClass(LocationService).singleton(),
    eventService: asClass(EventService).singleton(),
    rateLimitService: asClass(RateLimitService).singleton(),
  });
  // Provide legacy alias as a factory-backed wrapper so resolution occurs
  // from the test container cradle at call-time (scoped behavior).
  type Cradle = { rateLimitService?: RateLimitService } & Record<string, any>;
  function makeLegacyRateLimitWrapper(cradle: Cradle): RateLimitService {
    return {
      incrementAndCheck: (opts: LimitOptions) => (cradle.rateLimitService as RateLimitService).incrementAndCheck(opts),
      getCount: (opts: Omit<LimitOptions, 'limit'>) => (cradle.rateLimitService as RateLimitService).getCount(opts),
      resetWindow: (s: string, k: string, w: number) => (cradle.rateLimitService as RateLimitService).resetWindow(s, k, w),
    } as unknown as RateLimitService;
  }

  c.register({ rateLimit: asFunction((cradle: Cradle) => makeLegacyRateLimitWrapper(cradle)).scoped() });
  return c;
}
