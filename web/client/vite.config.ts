/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {defineConfig} from 'vite';
import vue from '@vitejs/plugin-vue';

// The client is built to ../public, which the Fastify server serves as static
// files in production. In dev, /api/* is proxied to the Fastify server so the
// SPA and the API share an origin.
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../public',
    emptyOutDir: true
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:3000'
    }
  }
});
