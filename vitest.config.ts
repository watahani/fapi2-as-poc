import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    // The in-repo conformance layer is a separate, intentionally-gated target
    // (npm run test:conformance / vitest.conformance.config.ts). It must not
    // turn the default green CI gate red before the P1 endpoints land.
    exclude: ["node_modules/**", "test/conformance/**"],
  },
});
