-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_UserMfaFactor" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "secret" TEXT,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "enrolledAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" DATETIME,
    "metadata" JSONB,
    "devices" JSONB,
    "catalogId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "UserMfaFactor_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "UserMfaFactor_catalogId_fkey" FOREIGN KEY ("catalogId") REFERENCES "AuthenticatorCatalog" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_UserMfaFactor" ("createdAt", "devices", "enabled", "enrolledAt", "id", "label", "lastUsedAt", "metadata", "secret", "status", "type", "updatedAt", "userId") SELECT "createdAt", "devices", "enabled", "enrolledAt", "id", "label", "lastUsedAt", "metadata", "secret", "status", "type", "updatedAt", "userId" FROM "UserMfaFactor";
DROP TABLE "UserMfaFactor";
ALTER TABLE "new_UserMfaFactor" RENAME TO "UserMfaFactor";
CREATE INDEX "UserMfaFactor_userId_idx" ON "UserMfaFactor"("userId");
CREATE INDEX "UserMfaFactor_userId_type_idx" ON "UserMfaFactor"("userId", "type");
CREATE INDEX "UserMfaFactor_catalogId_idx" ON "UserMfaFactor"("catalogId");
CREATE UNIQUE INDEX "UserMfaFactor_userId_catalogId_key" ON "UserMfaFactor"("userId", "catalogId");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
