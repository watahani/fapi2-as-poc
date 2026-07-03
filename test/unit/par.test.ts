/**
 * PAR endpoint behaviour over HTTP (docs/REQUIREMENTS-P1.md PAR-*),
 * exercising the real app via inject with the in-memory storage.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/index.js";
import { loadConfig } from "../../src/config.js";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";
import type { Storage } from "../../src/db/repositories/types.js";
import {
  ASSERTION_TYPE,
  createTestClient,
  form,
  makeClientAssertion,
  seedClient,
  type TestClient,
} from "../helpers/client.js";

const config = loadConfig({
  STORAGE: "memory",
  ISSUER: "https://as.example.com",
  RATE_LIMIT_PER_MIN: "0", // dedicated rate-limit test uses its own app
});

let app: FastifyInstance;
let storage: Storage;
let client: TestClient;

beforeAll(async () => {
  storage = createMemoryStorage();
  client = await createTestClient();
  await seedClient(storage, client);
  app = buildApp({ config, storage });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

async function par(params: Record<string, string | string[]>, opts: { auth?: boolean } = {}) {
  const base: Record<string, string> = {};
  if (opts.auth !== false) {
    base.client_assertion_type = ASSERTION_TYPE;
    base.client_assertion = await makeClientAssertion(client, config.issuer);
  }
  return app.inject({
    method: "POST",
    url: "/par",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({ ...base, ...params }),
  });
}

const goodRequest = () => ({
  response_type: "code",
  client_id: client.clientId,
  redirect_uri: client.redirectUri,
  scope: "openid",
  code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  code_challenge_method: "S256",
  state: "af0ifjsldkj",
  nonce: "n-0S6_WzA2Mj",
});

describe("POST /par", () => {
  it("returns 201 with a one-time urn request_uri and expires_in < 600 [RFC9126 §2.2; FAPI2 5.3.2.2(12)]", async () => {
    const res = await par(goodRequest());
    expect(res.statusCode).toBe(201);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    expect(res.headers["cache-control"]).toContain("no-store");
    const body = res.json() as { request_uri: string; expires_in: number };
    expect(body.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:[A-Za-z0-9_-]{43}$/);
    expect(body.expires_in).toBeGreaterThan(0);
    expect(body.expires_in).toBeLessThan(600);
  });

  it("binds the stored request to the authenticated client [RFC9126 §2.2]", async () => {
    const res = await par(goodRequest());
    const { request_uri } = res.json() as { request_uri: string };
    const stored = await storage.par.consume(request_uri, new Date());
    expect(stored?.clientId).toBe(client.clientId);
    expect(stored?.params.code_challenge).toBe(goodRequest().code_challenge);
  });

  it("stores dpop_jkt pushed alongside the request [RFC9449 §10.1]", async () => {
    const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
    const res = await par({ ...goodRequest(), dpop_jkt: jkt });
    const { request_uri } = res.json() as { request_uri: string };
    const stored = await storage.par.consume(request_uri, new Date());
    expect(stored?.dpopJkt).toBe(jkt);
  });

  it("rejects a pushed request_uri [RFC9126 §2.1]", async () => {
    const res = await par({ ...goodRequest(), request_uri: "urn:ietf:params:oauth:request_uri:x" });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_request");
  });

  it("rejects requests without client authentication [FAPI2 5.3.2.2(4)]", async () => {
    const res = await par(goodRequest(), { auth: false });
    expect(res.statusCode).toBe(401);
    expect((res.json() as { error: string }).error).toBe("invalid_client");
  });

  it("requires redirect_uri and rejects unregistered values [FAPI2 5.3.2.2(6); RFC9700 §2.1]", async () => {
    const { redirect_uri: _omit, ...rest } = goodRequest();
    expect((await par(rest)).statusCode).toBe(400);
    const res = await par({ ...goodRequest(), redirect_uri: "https://evil.example.com/cb" });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_request");
  });

  it("requires PKCE S256 [FAPI2 5.3.2.2(5); RFC7636 §4.4.1]", async () => {
    const { code_challenge: _omit, ...noChallenge } = goodRequest();
    const missing = await par(noChallenge);
    expect(missing.statusCode).toBe(400);
    expect((missing.json() as { error_description?: string }).error_description).toMatch(/code challenge/i);

    const plain = await par({ ...goodRequest(), code_challenge_method: "plain" });
    expect(plain.statusCode).toBe(400);

    const badFormat = await par({ ...goodRequest(), code_challenge: "tooshort" });
    expect(badFormat.statusCode).toBe(400);
  });

  it("rejects non-code response types [FAPI2 5.3.2.2(1)]", async () => {
    const res = await par({ ...goodRequest(), response_type: "token" });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("unsupported_response_type");
  });

  it("rejects scopes beyond the client registration [RFC6749 §3.3]", async () => {
    const res = await par({ ...goodRequest(), scope: "openid admin" });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_scope");
  });

  it("rejects repeated parameters [RFC6749 §3.1]", async () => {
    const res = await par({ ...goodRequest(), state: ["a", "b"] });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_request");
  });

  it("rejects a mismatching client_id [RFC9126 §2.1]", async () => {
    const res = await par({ ...goodRequest(), client_id: "someone-else" });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
  });

  it("answers non-POST methods with 405 [RFC9126 §2.3]", async () => {
    const res = await app.inject({ method: "GET", url: "/par" });
    expect(res.statusCode).toBe(405);
    expect(res.headers.allow).toBe("POST");
  });

  it("accepts OIDC display parameters without error [OIDC §15.1]", async () => {
    const res = await par({ ...goodRequest(), display: "page", ui_locales: "ja fr" });
    expect(res.statusCode).toBe(201);
  });

  it("carries recognised OIDC auth params through to storage [RFC9126 §2.2]", async () => {
    const res = await par({ ...goodRequest(), acr_values: "urn:acr:strong", max_age: "300" });
    const { request_uri } = res.json() as { request_uri: string };
    const stored = await storage.par.consume(request_uri, new Date());
    expect(stored?.params.acr_values).toBe("urn:acr:strong");
    expect(stored?.params.max_age).toBe("300");
  });

  it("treats a whitespace-only scope as the registered default [RFC6749 §3.3]", async () => {
    const res = await par({ ...goodRequest(), scope: " " });
    expect(res.statusCode).toBe(201);
    const { request_uri } = res.json() as { request_uri: string };
    const stored = await storage.par.consume(request_uri, new Date());
    expect(stored?.params.scope).toBe("openid");
  });

  it("accepts a mixed-case content-type [RFC9110 §8.3.1]", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/par",
      headers: { "content-type": "Application/X-WWW-Form-Urlencoded" },
      payload: form({
        client_assertion_type: ASSERTION_TYPE,
        client_assertion: await makeClientAssertion(client, config.issuer),
        ...goodRequest(),
      }),
    });
    expect(res.statusCode).toBe(201);
  });

  it("rejects prompt=none combined with other prompts [OIDC §3.1.2.1]", async () => {
    const res = await par({ ...goodRequest(), prompt: "none login" });
    expect(res.statusCode).toBe(400);
  });
});

describe("POST /par rate limiting [RFC9126 §2.3 / NFR-6]", () => {
  it("returns 429 above the per-source limit", async () => {
    const limited = buildApp({
      config: loadConfig({
        STORAGE: "memory",
        ISSUER: "https://as.example.com",
        RATE_LIMIT_PER_MIN: "2",
      }),
      storage,
    });
    await limited.ready();
    try {
      const send = () =>
        limited.inject({
          method: "POST",
          url: "/par",
          headers: { "content-type": "application/x-www-form-urlencoded" },
          payload: form(goodRequest()),
        });
      expect((await send()).statusCode).not.toBe(429);
      expect((await send()).statusCode).not.toBe(429);
      expect((await send()).statusCode).toBe(429);
    } finally {
      await limited.close();
    }
  });
});
