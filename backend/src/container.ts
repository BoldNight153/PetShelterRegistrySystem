import { createContainer, asClass, asValue, asFunction } from 'awilix';
import { UserService } from './services/userService';
import { RoleService } from './services/roleService';
import { prismaClient } from './prisma/client';
import { SettingsService } from './services/settingsService';
import { AuditService } from './services/auditService';
import { OwnerService } from './services/ownerService';
import { ShelterService } from './services/shelterService';
import { PetService } from './services/petService';
import { PetOwnerService } from './services/petOwnerService';
import { MedicalRecordService } from './services/medicalRecordService';
import { LocationService } from './services/locationService';
import { EventService } from './services/eventService';
import { AuthService } from './services/authService';
import { RateLimitService } from './services/rateLimitService';

export const container = createContainer();

container.register({
  prisma: asValue(prismaClient),
  userService: asClass(UserService).singleton(),
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
  authService: asClass(AuthService).singleton(),
  // register other services here as needed
});

// Provide a legacy alias 'rateLimit' that forwards calls to the canonical
// `rateLimitService` but uses the current DI scope (cradle) at runtime.
// We register a factory that returns a small typed wrapper. The factory
// itself does not resolve the canonical service, avoiding cyclic
// resolution; only the wrapper methods resolve the service from the
// provided cradle when invoked.
type Cradle = { rateLimitService?: RateLimitService } & Record<string, any>;

function makeLegacyRateLimitWrapper(cradle: Cradle): RateLimitService {
  return {
    incrementAndCheck: (opts: any) => {
      return (cradle.rateLimitService as RateLimitService).incrementAndCheck(opts);
    },
    getCount: (opts: any) => {
      return (cradle.rateLimitService as RateLimitService).getCount(opts);
    },
    resetWindow: (scope: string, key: string, windowMs: number) => {
      return (cradle.rateLimitService as RateLimitService).resetWindow(scope, key, windowMs);
    },
  } as unknown as RateLimitService;
}

// Register the factory as a scoped value so that when resolved from a
// request-scoped container the wrapper will use that scope's cradle to
// forward calls to the real service.
container.register({ rateLimit: asFunction((cradle: Cradle) => makeLegacyRateLimitWrapper(cradle)).scoped() });


export default container;
