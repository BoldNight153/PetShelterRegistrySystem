-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_AuthenticatorCatalog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "label" TEXT NOT NULL,
    "description" TEXT,
    "factorType" TEXT NOT NULL,
    "issuer" TEXT,
    "helper" TEXT,
    "docsUrl" TEXT,
    "tags" JSONB,
    "metadata" JSONB,
    "sortOrder" INTEGER NOT NULL DEFAULT 0,
    "isArchived" BOOLEAN NOT NULL DEFAULT false,
    "isSystem" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "createdBy" TEXT,
    "updatedBy" TEXT,
    "archivedAt" DATETIME,
    "archivedBy" TEXT
);
INSERT INTO "new_AuthenticatorCatalog" ("archivedAt", "archivedBy", "createdAt", "createdBy", "description", "docsUrl", "factorType", "helper", "id", "isArchived", "issuer", "label", "metadata", "sortOrder", "tags", "updatedAt", "updatedBy") SELECT "archivedAt", "archivedBy", "createdAt", "createdBy", "description", "docsUrl", "factorType", "helper", "id", "isArchived", "issuer", "label", "metadata", "sortOrder", "tags", "updatedAt", "updatedBy" FROM "AuthenticatorCatalog";
DROP TABLE "AuthenticatorCatalog";
ALTER TABLE "new_AuthenticatorCatalog" RENAME TO "AuthenticatorCatalog";
CREATE INDEX "AuthenticatorCatalog_isArchived_idx" ON "AuthenticatorCatalog"("isArchived");
CREATE INDEX "AuthenticatorCatalog_sortOrder_idx" ON "AuthenticatorCatalog"("sortOrder");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
