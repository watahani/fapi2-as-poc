/**
 * In-repo FAPI 2.0 Security Profile conformance suite.
 *
 * Boots the real AS (buildApp) and drives it over HTTP via light injection,
 * asserting the FAPI 2.0 SP requirements enumerated from the specs. This is the
 * runnable, Docker-free counterpart to the external OpenID Conformance Suite
 * (deploy/conformance/, gated until P3).
 *
 * STATUS: RED until P1. Every protocol endpoint is currently a no-op
 * (src/endpoints/index.ts), so these assertions fail — by design — and define
 * the behaviour P1 must implement. Each assertion cites its governing spec
 * section (CLAUDE.md §FAPI 実装方針 4 / docs/SPECS.md traceability).
 *
 * Sources of Trust:
 *   FAPI 2.0 Security Profile (final)         — referenced as [FAPI2 §x]
 *   RFC 9126 PAR / 7636 PKCE / 9207 iss
 *   RFC 9449 DPoP / 7523 private_key_jwt
 *   RFC 9068 JWT AT / 8414 AS Metadata / OIDC Discovery
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance, InjectOptions } from "fastify";
import { buildApp } from "../../src/index.js";
import { closePool } from "../../src/db/pool.js";

const ISSUER = "https://localhost:3000";

let app: FastifyInstance;

beforeAll(async () => {
  app = buildApp();
  await app.ready();
});

afterAll(async () => {
  await app.close();
  await closePool();
});

function inject(opts: InjectOptions) {
  return app.inject(opts);
}

/** OIDC Discovery / RFC 8414 metadata document, fetched once per test. */
async function discovery(): Promise<Record<string, unknown>> {
  const res = await inject({ method: "GET", url: "/.well-known/openid-configuration" });
  expect(res.statusCode, "discovery endpoint must exist [RFC8414 §3 / OIDD]").toBe(200);
  return res.json() as Record<string, unknown>;
}

describe("Discovery / AS Metadata [RFC 8414, OIDC Discovery, FAPI2 §5.3.2.1]", () => {
  it("publishes a discovery document at /.well-known/openid-configuration", async () => {
    const res = await inject({ method: "GET", url: "/.well-known/openid-configuration" });
    expect(res.statusCode).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
  });

  it("issuer matches configured issuer and is https without query/fragment [RFC8414 §2,§3.3; RFC9207 §2.3]", async () => {
    const md = await discovery();
    expect(md.issuer).toBe(ISSUER);
    const u = new URL(String(md.issuer));
    expect(u.protocol).toBe("https:");
    expect(u.search).toBe("");
    expect(u.hash).toBe("");
  });

  it("advertises only the authorization code flow [FAPI2 §5.3.2.2(1)]", async () => {
    const md = await discovery();
    expect(md.response_types_supported).toEqual(["code"]);
    const grants = (md.grant_types_supported as string[]) ?? [];
    expect(grants).toContain("authorization_code");
    expect(grants).not.toContain("implicit");
    expect(grants).not.toContain("password");
  });

  it("requires PAR and advertises the PAR endpoint [RFC9126 §5; FAPI2 §5.3.2.2(2,3)]", async () => {
    const md = await discovery();
    expect(md.require_pushed_authorization_requests).toBe(true);
    expect(String(md.pushed_authorization_request_endpoint)).toMatch(/^https:\/\//);
  });

  it("advertises PKCE S256 only [RFC7636; FAPI2 §5.3.2.2(5)]", async () => {
    const md = await discovery();
    expect(md.code_challenge_methods_supported).toEqual(["S256"]);
  });

  it("advertises iss authorization-response parameter support [RFC9207 §3]", async () => {
    const md = await discovery();
    expect(md.authorization_response_iss_parameter_supported).toBe(true);
  });

  it("restricts client auth to private_key_jwt (and/or mTLS) [FAPI2 §5.3.2.1(6)]", async () => {
    const md = await discovery();
    const methods = (md.token_endpoint_auth_methods_supported as string[]) ?? [];
    expect(methods).toContain("private_key_jwt");
    expect(methods).not.toContain("client_secret_basic");
    expect(methods).not.toContain("client_secret_post");
    expect(methods).not.toContain("none");
  });

  it("only offers safe signing algs — never 'none' [FAPI2 §5.4.1]", async () => {
    const md = await discovery();
    const allow = new Set(["PS256", "ES256", "EdDSA"]);
    for (const field of [
      "token_endpoint_auth_signing_alg_values_supported",
      "id_token_signing_alg_values_supported",
      "dpop_signing_alg_values_supported",
    ]) {
      const algs = (md[field] as string[] | undefined) ?? [];
      expect(algs.length, `${field} must be advertised`).toBeGreaterThan(0);
      expect(algs, `${field} must not include 'none'`).not.toContain("none");
      for (const a of algs) expect(allow.has(a), `${field}: ${a} not FAPI2-allowed`).toBe(true);
    }
  });

  it("advertises DPoP signing algs including ES256 [RFC9449 §5.1]", async () => {
    const md = await discovery();
    expect((md.dpop_signing_alg_values_supported as string[]) ?? []).toContain("ES256");
  });

  it("exposes authorization_endpoint, token_endpoint, jwks_uri over https [RFC8414 §2]", async () => {
    const md = await discovery();
    for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) {
      expect(String(md[k]), `${k} must be https`).toMatch(/^https:\/\//);
    }
  });
});

describe("JWKS [RFC 7517/7518, FAPI2 §5.4]", () => {
  it("serves a JWKS with ES256 P-256 signing keys and NO private material", async () => {
    const md = await discovery();
    const jwksUrl = new URL(String(md.jwks_uri)).pathname;
    const res = await inject({ method: "GET", url: jwksUrl });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { keys?: Array<Record<string, unknown>> };
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys!.length).toBeGreaterThan(0);
    for (const k of body.keys!) {
      expect(k.kid, "each key needs a kid for rotation [FAPI2 §5.4.2]").toBeTruthy();
      expect(k).not.toHaveProperty("d"); // never leak EC/RSA private component
      if (k.kty === "EC") expect(k.crv).toBe("P-256"); // ES256
    }
  });
});

describe("PAR endpoint [RFC 9126, FAPI2 §5.3.2.2]", () => {
  it("rejects an unauthenticated PAR request [FAPI2 §5.3.2.2(4)]", async () => {
    const res = await inject({
      method: "POST",
      url: "/par",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "response_type=code&client_id=x&redirect_uri=https://c.example/cb&scope=openid",
    });
    // Client auth missing → invalid_client. Anything but a 2xx success.
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect((res.json() as { error?: string }).error).toBe("invalid_client");
  });

  it("rejects a request_uri parameter pushed to the PAR endpoint [RFC9126 §2.1]", async () => {
    const res = await inject({
      method: "POST",
      url: "/par",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "request_uri=urn:ietf:params:oauth:request_uri:abc",
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect((res.json() as { error?: string }).error).toBe("invalid_request");
  });

  it("rejects non-POST methods on the PAR endpoint [RFC9126 §2.3]", async () => {
    const res = await inject({ method: "GET", url: "/par" });
    expect(res.statusCode).toBe(405);
  });
});

describe("Authorization endpoint [RFC 6749, RFC 9126, RFC 9207, FAPI2 §5.3.2.2]", () => {
  it("rejects a non-PAR authorization request (request_uri required) [FAPI2 §5.3.2.2(3)]", async () => {
    const res = await inject({
      method: "GET",
      url: "/authorize?response_type=code&client_id=x&redirect_uri=https://c.example/cb&scope=openid&code_challenge=abc&code_challenge_method=S256",
    });
    // PAR-required: a direct authorization request must not start a flow.
    expect([302, 303, 400]).toContain(res.statusCode);
    if (res.statusCode === 400) {
      expect((res.json() as { error?: string }).error).toBe("invalid_request");
    }
  });

  it("rejects implicit/hybrid response types [FAPI2 §5.3.2.2(1)]", async () => {
    const res = await inject({
      method: "GET",
      url: "/authorize?response_type=token&client_id=x&request_uri=urn:ietf:params:oauth:request_uri:abc",
    });
    expect(res.statusCode).not.toBe(200);
    // unsupported_response_type either as JSON error or redirected error param.
    const body = res.payload.includes("error") ? res.payload : "";
    expect(res.statusCode >= 400 || body.includes("unsupported_response_type")).toBe(true);
  });
});

describe("Token endpoint [RFC 6749, RFC 7523, RFC 9449, RFC 9068]", () => {
  it("rejects the prohibited password grant [FAPI2 §5.3.2.1(2)]", async () => {
    const res = await inject({
      method: "POST",
      url: "/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "grant_type=password&username=u&password=p",
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect((res.json() as { error?: string }).error).toMatch(
      /unsupported_grant_type|invalid_client|invalid_request/,
    );
  });

  it("requires client authentication on the token endpoint [RFC6749 §3.2.1; FAPI2 §5.3.2.1(3)]", async () => {
    const res = await inject({
      method: "POST",
      url: "/token",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: "grant_type=authorization_code&code=abc&redirect_uri=https://c.example/cb",
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect((res.json() as { error?: string }).error).toBe("invalid_client");
  });
});
