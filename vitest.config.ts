import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: { conditions: ['@xiezhi/source'] },
  ssr: { resolve: { conditions: ['@xiezhi/source'] } },
  test: {
    include: ['packages/*/test/**/*.test.ts', 'apps/*/test/**/*.test.ts'],
    testTimeout: 30_000,
    pool: 'forks',
    passWithNoTests: true,
  },
});
