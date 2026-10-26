import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.spec.ts"],
    // Loads the Reflect polyfill tsyringe needs before any spec imports the library.
    setupFiles: ["vitest.setup.ts"],
    // Carried over from the old config: RSA key generation can be slow on CI runners.
    testTimeout: 10000,
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: ["src/**/*"],
      exclude: ["src/**/*.spec.ts", "build/**"],
    },
  },
});
