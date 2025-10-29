import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: 'localhost', // Only listen on localhost, not network interfaces
    port: 5173,
    proxy: {
      // Forward API requests to the backend during development
      '/api': {
        target: process.env.VITE_BACKEND_URL || 'http://localhost:5500',
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
