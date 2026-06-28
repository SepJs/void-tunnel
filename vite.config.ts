// vite.config.ts - Vite Bundler Configuration mapping root assets to src folder
import { defineConfig } from 'vite';

export default defineConfig({
  // Set the development server root to the "src" subdirectory
  root: 'src',
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    // Compile and bundle production assets into "../dist" at the project root
    outDir: '../dist',
    emptyOutDir: true,
  }
});