import { describe, expect, it } from "vitest";
import { endpointUrls, loadConfig } from "../../src/config.js";

const base = { STORAGE: "memory" } as NodeJS.ProcessEnv;

describe("loadConfig", () => {
  it("applies FAPI2-safe defaults", () => {
    const c = loadConfig(base);
    expect(c.issuer).toBe("https://localhost:3000");
    // FAPI2-GEN-11: auth code lifetime <= 60s.
    expect(c.authCodeTtlSec).toBeLessThanOrEqual(60);
    // FAPI2-AUTHZ-12: PAR request_uri lifetime < 600s.
    expect(c.parTtlSec).toBeLessThan(600);
    // FAPI2-GEN-13: future skew acceptance within 0..60s.
    expect(c.clockSkewFutureAcceptSec).toBeGreaterThanOrEqual(0);
    expect(c.clockSkewFutureAcceptSec).toBeLessThanOrEqual(60);
    // JWTAT-6: default resource indicator falls back to the issuer.
    expect(c.accessTokenAudience).toBe(c.issuer);
  });

  it("rejects auth code TTLs beyond 60s [FAPI2 5.3.2.1(11)]", () => {
    expect(() => loadConfig({ ...base, AUTH_CODE_TTL_SEC: "61" })).toThrow();
  });

  it("rejects PAR TTLs of 600s or more [FAPI2 5.3.2.2(12)]", () => {
    expect(() => loadConfig({ ...base, PAR_TTL_SEC: "600" })).toThrow();
  });

  it("rejects non-https issuers on non-loopback hosts [RFC8414 §2]", () => {
    expect(() => loadConfig({ ...base, ISSUER: "http://as.example.com" })).toThrow(/https/);
  });

  it("tolerates http loopback issuers outside production (local conformance harness)", () => {
    const c = loadConfig({ ...base, ISSUER: "http://localhost:3000" });
    expect(c.issuer).toBe("http://localhost:3000");
  });

  it("rejects issuers with query or fragment, including bare delimiters [RFC8414 §2]", () => {
    expect(() => loadConfig({ ...base, ISSUER: "https://as.example.com/?x=1" })).toThrow();
    expect(() => loadConfig({ ...base, ISSUER: "https://as.example.com?" })).toThrow();
    expect(() => loadConfig({ ...base, ISSUER: "https://as.example.com#" })).toThrow();
  });

  it("rejects a trailing slash (issuer comparison is byte-for-byte) [RFC8414 §3.3]", () => {
    expect(() => loadConfig({ ...base, ISSUER: "https://as.example.com/" })).toThrow(/trailing/);
    expect(() => loadConfig({ ...base, ISSUER: "https://as.example.com/tenant/" })).toThrow(/trailing/);
  });

  const prodBase = {
    NODE_ENV: "production",
    ISSUER: "https://as.example.com",
    PDP_KIND: "authzen-http",
    DATABASE_URL: "postgresql://u:p@db.internal:5432/as",
    DATABASE_SSL: "true",
    KEYSTORE_KEK: Buffer.alloc(32, 7).toString("base64"),
    SESSION_SECRET: "prod-session-secret-at-least-32-characters-long",
  } as NodeJS.ProcessEnv;

  it("fails closed in production (memory storage, mock PDP, dev DB, http/loopback issuer, no KEK/TLS/session)", () => {
    expect(() => loadConfig({ ...prodBase, STORAGE: "memory" })).toThrow(/STORAGE/);
    expect(() => loadConfig({ ...prodBase, PDP_KIND: "mock" })).toThrow(/PDP_KIND/);
    expect(() => loadConfig({ ...prodBase, ISSUER: "https://localhost:3000" })).toThrow(/loopback/);
    expect(() => loadConfig({ ...prodBase, ISSUER: "http://as.example.com" })).toThrow(/https/);
    expect(() =>
      loadConfig({ ...prodBase, DATABASE_URL: "postgresql://u:devpassword@db.internal:5432/as" }),
    ).toThrow(/DATABASE_URL/);
    expect(() =>
      loadConfig({ ...prodBase, DATABASE_URL: "postgresql://u:p@127.0.0.1:5432/as" }),
    ).toThrow(/DATABASE_URL/);
    expect(() => loadConfig({ ...prodBase, DATABASE_SSL: "false" })).toThrow(/DATABASE_SSL/);
    expect(() => loadConfig({ ...prodBase, KEYSTORE_KEK: "" })).toThrow(/KEYSTORE_KEK/);
    expect(() => loadConfig({ ...prodBase, SESSION_SECRET: "" })).toThrow(/SESSION_SECRET/);
  });

  it("accepts a fully-configured production environment", () => {
    const c = loadConfig(prodBase);
    expect(c.devModeWarnings).toEqual([]);
    expect(c.keystoreKek?.length).toBe(32);
  });

  it("does not reject production hostnames merely containing 'localhost'", () => {
    const c = loadConfig({ ...prodBase, ISSUER: "https://api.localhost-gateway.example.com" });
    expect(c.issuer).toBe("https://api.localhost-gateway.example.com");
  });

  it("rejects a malformed KEYSTORE_KEK", () => {
    expect(() => loadConfig({ ...base, KEYSTORE_KEK: "dG9vc2hvcnQ=" })).toThrow(/32 bytes/);
  });

  it("rejects a too-short SESSION_SECRET / DPOP_NONCE_SECRET (brute-forceable)", () => {
    expect(() => loadConfig({ ...base, SESSION_SECRET: "short" })).toThrow(/SESSION_SECRET/);
    expect(() => loadConfig({ ...base, DPOP_NONCE_SECRET: "short" })).toThrow(/DPOP_NONCE_SECRET/);
  });

  it("itemises dev-grade settings for boot-time warnings", () => {
    const c = loadConfig(base);
    expect(c.devModeWarnings.join(" ")).toMatch(/PDP_KIND=mock/);
    expect(c.devModeWarnings.join(" ")).toMatch(/KEYSTORE_KEK/);
  });
});

describe("endpointUrls", () => {
  it("derives every endpoint from the issuer (never request headers)", () => {
    const c = loadConfig({ ...base, ISSUER: "https://as.example.com" });
    const urls = endpointUrls(c);
    expect(urls.authorization).toBe("https://as.example.com/authorize");
    expect(urls.token).toBe("https://as.example.com/token");
    expect(urls.par).toBe("https://as.example.com/par");
    expect(urls.jwks).toBe("https://as.example.com/jwks");
  });
});

import { sanitizeErrorDescription } from "../../src/domain/errors.js";

describe("sanitizeErrorDescription [RFC6749 §5.2 NQSCHAR]", () => {
  it("strips characters outside the allowed set (e.g. the section sign)", () => {
    const out = sanitizeErrorDescription("PKCE verification failed [RFC7636 §4.6]");
    expect(out).toBe("PKCE verification failed [RFC7636 4.6]");
    expect(/[^\t\n\r\x20-\x21\x23-\x5b\x5d-\x7e]/.test(out)).toBe(false);
  });
  it('removes the forbidden " and \\ characters', () => {
    const out = sanitizeErrorDescription('bad "quote" and \\ backslash');
    expect(out).not.toMatch(/["\\]/);
  });
});
