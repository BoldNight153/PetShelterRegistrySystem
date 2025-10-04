import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  optimizeDeps: {
    include: ["redoc"],
  },
  server: {
    proxy: {
      "/api-docs": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      // Simple health check proxy so the frontend can query `/health` without CORS in dev
      "/health": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
    },
  },
})