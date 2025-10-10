-- CreateTable
CREATE TABLE "MetricPoint" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "metric" TEXT NOT NULL,
    "value" REAL NOT NULL,
    "labels" JSONB,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateIndex
CREATE INDEX "MetricPoint_metric_createdAt_idx" ON "MetricPoint"("metric", "createdAt");
