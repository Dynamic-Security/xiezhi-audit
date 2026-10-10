import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev only: proxy the API to a running `xiezhi serve` and present its own Origin/Host, because
// the service rejects foreign origins. Production serves the built files from the service.
const target = process.env.XIEZHI_AUDIT_API ?? 'http://127.0.0.1:4820';

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false, chunkSizeWarningLimit: 1500 },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target, changeOrigin: true,
        configure: (proxy) => proxy.on('proxyReq', (req) => { if (req.getHeader('origin')) req.setHeader('origin', target); }),
      },
    },
  },
});
