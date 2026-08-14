import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "src/**/*.spec.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      reportsDirectory: "./coverage",
      // J02 — `all: true` so coverage counts untested source files and can
      // fail; thresholds set at the measured floor (ratchet may only rise).
      all: true,
      include: ["src/**"],
      thresholds: {
        lines: 35,
        functions: 40,
        branches: 35,
        statements: 35,
      },
      exclude: [
        "src/**/*.test.ts",
        "src/**/*.spec.ts",
        "src/**/__tests__/**",
        "src/index.ts",
      ],
    },
  },
});
