import { defineConfig } from "vitest/config";

/**
 * In-repo FAPI 2.0 SP conformance layer.
 *
 * Boots the actual AS (buildApp) and drives it over HTTP, asserting FAPI 2.0
 * Security Profile behaviour directly — no Docker, no external suite, runs in
 * any CI. This is the fast feedback loop / TDD baseline that complements the
 * external OpenID Conformance Suite (deploy/conformance/, gated until P3).
 *
 * Kept OUT of the default `npm test` run (vitest.config.ts excludes this dir)
 * so the green CI gate stays green; conformance is intentionally gated until
 * the protocol endpoints exist (see docs/GOALS.md phase plan). Run explicitly:
 *   npm run test:conformance
 */
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/conformance/**/*.test.ts"],
    // No DB required: every endpoint is unimplemented (404) until P1, and the
    // assertions target metadata/validation behaviour rather than persistence.
  },
});
