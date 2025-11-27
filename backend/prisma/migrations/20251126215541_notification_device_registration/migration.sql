-- CreateTable
CREATE TABLE "NotificationDeviceRegistration" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "userId" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "platform" TEXT NOT NULL DEFAULT 'unknown',
    "transport" TEXT NOT NULL DEFAULT 'web_push',
    "fingerprint" TEXT,
    "subscription" JSONB,
    "token" TEXT,
    "status" TEXT NOT NULL DEFAULT 'active',
    "userAgent" TEXT,
    "ipAddress" TEXT,
    "registeredAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" DATETIME,
    "revokedAt" DATETIME,
    "metadata" JSONB,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "NotificationDeviceRegistration_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

-- CreateIndex
CREATE INDEX "NotificationDeviceRegistration_userId_idx" ON "NotificationDeviceRegistration"("userId");

-- CreateIndex
CREATE INDEX "NotificationDeviceRegistration_userId_status_idx" ON "NotificationDeviceRegistration"("userId", "status");

-- CreateIndex
CREATE INDEX "NotificationDeviceRegistration_fingerprint_idx" ON "NotificationDeviceRegistration"("fingerprint");
