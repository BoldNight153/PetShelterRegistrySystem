/*
  Warnings:

  - You are about to alter the column `metadata` on the `User` table. The data in that column could be lost. The data in that column will be cast from `String` to `Json`.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Pet" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "species" TEXT NOT NULL,
    "breed" TEXT,
    "sex" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "dob" DATETIME,
    "microchip" TEXT,
    "color" TEXT,
    "weightKg" REAL,
    "sterilized" BOOLEAN NOT NULL DEFAULT false,
    "status" TEXT NOT NULL DEFAULT 'AVAILABLE',
    "isAlive" BOOLEAN NOT NULL DEFAULT true,
    "deceasedAt" DATETIME,
    "notes" TEXT,
    "intakeAt" DATETIME,
    "shelterId" TEXT,
    "locationId" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Pet_shelterId_fkey" FOREIGN KEY ("shelterId") REFERENCES "Shelter" ("id") ON DELETE RESTRICT ON UPDATE CASCADE,
    CONSTRAINT "Pet_locationId_fkey" FOREIGN KEY ("locationId") REFERENCES "Location" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Pet" ("breed", "color", "createdAt", "deceasedAt", "dob", "id", "intakeAt", "isAlive", "locationId", "microchip", "name", "notes", "sex", "shelterId", "species", "status", "sterilized", "updatedAt", "weightKg") SELECT "breed", "color", "createdAt", "deceasedAt", "dob", "id", "intakeAt", "isAlive", "locationId", "microchip", "name", "notes", "sex", "shelterId", "species", "status", "sterilized", "updatedAt", "weightKg" FROM "Pet";
DROP TABLE "Pet";
ALTER TABLE "new_Pet" RENAME TO "Pet";
CREATE UNIQUE INDEX "Pet_microchip_key" ON "Pet"("microchip");
CREATE INDEX "Pet_name_idx" ON "Pet"("name");
CREATE INDEX "Pet_species_idx" ON "Pet"("species");
CREATE TABLE "new_User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "emailVerified" DATETIME,
    "passwordHash" TEXT,
    "name" TEXT,
    "image" TEXT,
    "metadata" JSONB,
    "lastLoginAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_User" ("createdAt", "email", "emailVerified", "id", "image", "metadata", "name", "passwordHash", "updatedAt") SELECT "createdAt", "email", "emailVerified", "id", "image", "metadata", "name", "passwordHash", "updatedAt" FROM "User";
DROP TABLE "User";
ALTER TABLE "new_User" RENAME TO "User";
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
