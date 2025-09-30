import { defineConfig } from 'vite';

// Load ESM-only plugins using dynamic import inside an async config factory.
import path from 'path';

export default defineConfig(async () => {
  const reactPlugin = (await import('@vitejs/plugin-react')).default;

  return {
    plugins: [reactPlugin()],
    resolve: {
      alias: {
        '@/': path.resolve(new URL('.', import.meta.url).pathname, 'src') + '/',
      }
    },
    server: {
      proxy: {
        // Proxy /api/* to the backend and remove the /api prefix so
        // requests like /api/pets -> http://localhost:4000/pets
        '/api': {
          target: 'http://localhost:4000',
          changeOrigin: true,
          rewrite: (path: string) => path.replace(/^\/api/, '')
        }
      }
    }
  };
});
