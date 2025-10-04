import path from "path"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  // Ensure Vite caches live under node_modules/.vite inside frontend, not in project root or legacy folders
  cacheDir: path.resolve(__dirname, "node_modules/.vite"),
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
    },
  },
})