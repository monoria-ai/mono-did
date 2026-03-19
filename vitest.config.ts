import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.{test,spec}.ts'],
  },
  resolve: {
    alias: {
      '@mono/did': resolve(__dirname, 'packages/mono-did/src/index.ts'),
      '@mono/did-core-types': resolve(__dirname, 'packages/did-core-types/src/index.ts'),
      '@mono/adapters': resolve(__dirname, 'packages/mono-adapters/src/index.ts'),
      '@mono/identity': resolve(__dirname, 'packages/mono-identity/src/index.ts'),
      '@mono/handshake': resolve(__dirname, 'packages/mono-handshake/src/index.ts'),
      '@mono/protocol': resolve(__dirname, 'packages/mono-protocol/src/index.ts'),
    },
  },
});
