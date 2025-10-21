// eslint-disable-next-line import/no-unresolved
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["test/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}", "test/**/*.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov", "text-summary"],
      include: ["src/**/*.ts"],
      exclude: ["**/*.d.ts"],
    },
    testTimeout: 10000,
  },
});
