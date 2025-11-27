import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    fileParallelism: false,
    globals: true,
    environment: 'node',
    testTimeout: 10000,
    hookTimeout: 10000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['index.js', 'lib/**/*.js'],
      exclude: ['test/**', 'node_modules/**'],
    },
    include: ['test/**/*.js'],
    exclude: ['test/types/**'],
  },
});
