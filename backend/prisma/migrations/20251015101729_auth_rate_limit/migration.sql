-- CreateTable
CREATE TABLE "RateLimit" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scope" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "windowStart" DATETIME NOT NULL,
    "count" INTEGER NOT NULL DEFAULT 0,
    "lastAttemptAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX "RateLimit_scope_key_windowStart_idx" ON "RateLimit"("scope", "key", "windowStart");

-- CreateIndex
CREATE UNIQUE INDEX "RateLimit_scope_key_windowStart_key" ON "RateLimit"("scope", "key", "windowStart");
