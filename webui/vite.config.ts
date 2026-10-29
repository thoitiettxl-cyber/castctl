import { defineConfig, type Plugin } from 'vite';
import react from '@vitejs/plugin-react';
import { viteSingleFile } from 'vite-plugin-singlefile';
import path from 'path';
import { execSync } from 'child_process';
import fs from 'fs';
import { registerMockApi } from './dev-mocks/mockServer';

// Get version from environment, git tag, or package.json
function getVersion(): string {
  // 1. Environment variable (set by GitHub Actions)
  if (process.env.VERSION) {
    return process.env.VERSION;
  }

  // 2. Try git tag
  try {
    const gitTag = execSync('git describe --tags --exact-match 2>/dev/null || git describe --tags 2>/dev/null || echo ""', { encoding: 'utf8' }).trim();
    if (gitTag) {
      return gitTag;
    }
  } catch {
    // Git not available or no tags
  }

  // 3. Fall back to package.json version
  try {
    const pkg = JSON.parse(fs.readFileSync(path.resolve(__dirname, 'package.json'), 'utf8'));
    if (pkg.version && pkg.version !== '0.0.0') {
      return pkg.version;
    }
  } catch {
    // package.json not readable
  }

  return 'dev';
}

const USE_MOCKS = process.env.VITE_USE_MOCKS === 'true';
const SCREENCAST_LOGIN_ENABLED = process.env.VITE_ENABLE_SCREENCAST_LOGIN === 'true';

/**
 * Dev-only mock API middleware. Active ONLY when VITE_USE_MOCKS=true on the
 * Vite dev server (`bun run dev:mocks`). This plugin runs in Node at dev
 * time; it is never bundled into dist/index.html, so production builds
 * contain no mock code paths. Fixtures live in dev-mocks/ (Node-only).
 * The dev server binds loopback only (see package.json dev:mocks script).
 */
function mockApiPlugin(): Plugin {
  return {
    name: 'castctl-mock-api',
    configureServer(server) {
      if (!USE_MOCKS) return;
      // Static import (Node-side config only): the middleware must be
      // registered synchronously, before the SPA fallback. A lazy dynamic
      // import here silently never ran. This module is never bundled into
      // dist/index.html — vite.config.ts is build-time only.
      registerMockApi(server.middlewares);
      console.log('[castctl-mock-api] mock /api/v1 enabled (dev only)');
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), viteSingleFile({ removeViteModuleLoader: true }), mockApiPlugin()],
  define: {
    __APP_VERSION__: JSON.stringify(getVersion()),
    __CASTCTL_USE_MOCKS__: JSON.stringify(USE_MOCKS),
    __CASTCTL_SCREENCAST_LOGIN__: JSON.stringify(SCREENCAST_LOGIN_ENABLED),
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  css: {
    modules: {
      localsConvention: 'camelCase',
      generateScopedName: '[name]__[local]___[hash:base64:5]',
    },
    preprocessorOptions: {
      scss: {
        additionalData: `@use "@/styles/variables.scss" as *;`,
      },
    },
  },
  build: {
    target: 'es2020',
    outDir: 'dist',
    assetsInlineLimit: 100000000,
    chunkSizeWarningLimit: 100000000,
    cssCodeSplit: false,
    rolldownOptions: {
      output: {
        codeSplitting: false,
      },
    },
  },
});
