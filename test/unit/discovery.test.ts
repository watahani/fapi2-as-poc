import { describe, expect, it } from "vitest";
import { buildMetadata, wellKnownPaths } from "../../src/endpoints/discovery.js";
import { loadConfig } from "../../src/config.js";

const config = loadConfig({ STORAGE: "memory", ISSUER: "https://as.example.com" });

describe("wellKnownPaths", () => {
  it("appends the OIDC suffix after the issuer path [OIDD §4]", () => {
    expect(wellKnownPaths("https://as.example.com").oidc).toBe(
      "/.well-known/openid-configuration",
    );
    expect(wellKnownPaths("https://as.example.com/issuer1").oidc).toBe(
      "/issuer1/.well-known/openid-configuration",
    );
  });

  it("inserts the RFC 8414 suffix between host and issuer path [RFC8414 §3]", () => {
    expect(wellKnownPaths("https://as.example.com").oauth).toBe(
      "/.well-known/oauth-authorization-server",
    );
    expect(wellKnownPaths("https://as.example.com/issuer1").oauth).toBe(
      "/.well-known/oauth-authorization-server/issuer1",
    );
  });
});

describe("buildMetadata", () => {
  const md = buildMetadata(config);

  it("issuer matches the configured issuer byte-for-byte [RFC8414 §3.3 / DISC-3]", () => {
    expect(md.issuer).toBe("https://as.example.com");
  });

  it("advertises the FAPI2 profile shape", () => {
    expect(md.response_types_supported).toEqual(["code"]); // FAPI2-AUTHZ-1
    expect(md.require_pushed_authorization_requests).toBe(true); // PAR-13
    expect(md.code_challenge_methods_supported).toEqual(["S256"]); // PKCE-9
    expect(md.authorization_response_iss_parameter_supported).toBe(true); // ISS-3
    expect(md.token_endpoint_auth_methods_supported).toEqual(["private_key_jwt"]); // FAPI2-GEN-6
  });

  it("only advertises FAPI2-allowed JWS algorithms [FAPI2 5.4.1]", () => {
    const allowed = new Set(["PS256", "ES256", "EdDSA"]);
    for (const field of [
      "token_endpoint_auth_signing_alg_values_supported",
      "id_token_signing_alg_values_supported",
      "dpop_signing_alg_values_supported",
      "revocation_endpoint_auth_signing_alg_values_supported",
      "introspection_endpoint_auth_signing_alg_values_supported",
    ]) {
      const algs = md[field] as string[];
      expect(algs.length).toBeGreaterThan(0);
      for (const alg of algs) expect(allowed.has(alg)).toBe(true);
    }
  });

  it("derives every advertised URL from the issuer [RFC8414 §2]", () => {
    for (const field of [
      "authorization_endpoint",
      "token_endpoint",
      "jwks_uri",
      "pushed_authorization_request_endpoint",
      "revocation_endpoint",
      "introspection_endpoint",
    ]) {
      expect(String(md[field])).toMatch(/^https:\/\/as\.example\.com\//);
    }
  });

  it("omits empty-array claims [RFC8414 §3.2 / DISC-6]", () => {
    for (const value of Object.values(md)) {
      if (Array.isArray(value)) expect(value.length).toBeGreaterThan(0);
    }
  });

  it("defaults preserve the current FAPI2 SP profile shape (behaviour-preserving)", () => {
    expect(md.scopes_supported).toEqual(["openid", "profile"]);
    expect(md.subject_types_supported).toEqual(["public"]);
    expect(md.id_token_signing_alg_values_supported).toEqual(["ES256"]);
    expect(md.dpop_signing_alg_values_supported).toEqual(["ES256", "PS256", "EdDSA"]);
    expect(md.token_endpoint_auth_signing_alg_values_supported).toEqual(["ES256", "PS256", "EdDSA"]);
    expect(md.claims_supported).toEqual(["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"]);
  });

  it("is driven by config.metadata so operators can widen sets within FAPI2", () => {
    const custom = loadConfig({
      STORAGE: "memory",
      ISSUER: "https://as.example.com",
      METADATA_SCOPES_SUPPORTED: "openid, profile, email",
      METADATA_DPOP_SIGNING_ALGS: "ES256,PS256",
    });
    const cmd = buildMetadata(custom);
    expect(cmd.scopes_supported).toEqual(["openid", "profile", "email"]);
    expect(cmd.dpop_signing_alg_values_supported).toEqual(["ES256", "PS256"]);
  });
});
