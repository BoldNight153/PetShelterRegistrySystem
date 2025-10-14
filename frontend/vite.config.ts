import path from "path"
import fs from "fs"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

// https://vite.dev/config/
export default defineConfig({
  // Ensure Vite caches live under node_modules/.vite inside frontend, not in project root or legacy folders
  cacheDir: path.resolve(__dirname, "node_modules/.vite"),
  plugins: [
    // Intercept SPA routes that could be mistaken for API by proxy (e.g. /admin/audit-logs)
    {
      name: "admin-spa-fallback",
      configureServer(server) {
        server.middlewares.use(async (req, res, next) => {
          const url = req.url || "";
          const accept = req.headers["accept"] || "";
          // Only handle top-level browser navigations that want HTML and are not static assets
          const isHtml = typeof accept === "string" && accept.includes("text/html");
          const hasExt = !!path.extname(url.split("?")[0] || "");
          if (
            req.method === "GET" &&
            isHtml &&
            !hasExt &&
            // Ensure SPA routes under /admin that must NOT be proxied to backend
            (url.startsWith("/admin/audit-logs") || url === "/admin" || url.startsWith("/admin/") && !url.startsWith("/admin/audit") && !url.startsWith("/admin/monitoring") && !url.startsWith("/admin/docs"))
          ) {
            try {
              const indexPath = path.resolve(__dirname, "index.html");
              const raw = fs.readFileSync(indexPath, "utf-8");
              const html = await server.transformIndexHtml(url, raw);
              res.statusCode = 200;
              res.setHeader("Content-Type", "text/html");
              res.end(html);
              return;
            } catch {
              // Fall through to next middleware if anything goes wrong
            }
          }
          next();
        });
      },
    },
    react(),
    tailwindcss(),
  ],
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
      "/admin/audit": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      "/api-docs": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      "/auth": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      "/admin/monitoring": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      "/admin/docs": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      "/health": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      "/healthz": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
      "/readyz": {
        target: "http://localhost:4000",
        changeOrigin: true,
      },
    },
  },
})