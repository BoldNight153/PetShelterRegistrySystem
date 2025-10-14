# System Architecture

This document describes the overall system architecture.

## Overview

- Backend: Express (TypeScript), Prisma ORM, JWT in cookies, CSRF protection, RBAC, monitoring.
- Frontend: React + Vite + Tailwind, Admin UI with protected routes, ReDoc docs viewer.
- Database: SQLite/Prisma dev DB; migrate to other RDBMS in production.

## Request Flow

1. Client requests protected resource.
2. Auth middleware validates session from cookies.
3. CSRF header required for state-changing requests.
4. RBAC checks ensure the user has access.

## Monitoring

- Metrics snapshot persisted with retention policy.

## Future Work

- Horizontal scaling, background workers, job queues.
