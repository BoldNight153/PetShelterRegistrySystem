## Multi-stage Dockerfile for Node.js app
FROM node:20-bullseye-slim AS builder
WORKDIR /app

# Install all dependencies (including dev deps needed for prisma CLI)
COPY package*.json ./
# Install only production dependencies to keep the build small and avoid legacy dev deps
RUN npm ci --omit=dev

# Install only the Prisma CLI (needed to run generate/migrate in build/entrypoint)
RUN npm install --no-save prisma

# Copy app source
COPY . .

# Generate Prisma client during build so @prisma/client and generated client are available
RUN npx prisma generate

FROM node:20-bullseye-slim AS runtime
WORKDIR /app

# Copy everything from the builder (includes node_modules and generated prisma client)
COPY --from=builder /app /app

ENV NODE_ENV=production
EXPOSE 3000

# Ensure entrypoint is executable and run it (migrates DB then starts the app)
RUN chmod +x ./docker-entrypoint.sh
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node", "app.js"]
