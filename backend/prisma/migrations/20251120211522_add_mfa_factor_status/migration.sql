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
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "UserMfaFactor_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_UserMfaFactor" ("createdAt", "devices", "enabled", "enrolledAt", "id", "label", "lastUsedAt", "metadata", "secret", "type", "updatedAt", "userId") SELECT "createdAt", "devices", "enabled", "enrolledAt", "id", "label", "lastUsedAt", "metadata", "secret", "type", "updatedAt", "userId" FROM "UserMfaFactor";
DROP TABLE "UserMfaFactor";
ALTER TABLE "new_UserMfaFactor" RENAME TO "UserMfaFactor";
CREATE INDEX "UserMfaFactor_userId_idx" ON "UserMfaFactor"("userId");
CREATE INDEX "UserMfaFactor_userId_type_idx" ON "UserMfaFactor"("userId", "type");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
