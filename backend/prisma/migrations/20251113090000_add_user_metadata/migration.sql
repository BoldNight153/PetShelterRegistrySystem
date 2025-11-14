-- Add metadata column to store structured profile details
-- Use a generic ADD clause (some SQL engines reject the 'COLUMN' keyword)
ALTER TABLE "User" ADD "metadata" TEXT;
