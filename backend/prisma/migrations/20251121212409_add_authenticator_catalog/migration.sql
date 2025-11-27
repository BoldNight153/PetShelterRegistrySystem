-- CreateTable
CREATE TABLE "AuthenticatorCatalog" (
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
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "createdBy" TEXT,
    "updatedBy" TEXT,
    "archivedAt" DATETIME,
    "archivedBy" TEXT
);

-- CreateIndex
CREATE INDEX "AuthenticatorCatalog_isArchived_idx" ON "AuthenticatorCatalog"("isArchived");

-- CreateIndex
CREATE INDEX "AuthenticatorCatalog_sortOrder_idx" ON "AuthenticatorCatalog"("sortOrder");
