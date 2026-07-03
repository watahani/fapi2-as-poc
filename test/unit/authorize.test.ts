/**
 * Authorization endpoint + interactive login/consent (P2)
 * (docs/REQUIREMENTS-P1.md OIDC-*, ISS-*, FAPI2-AUTHZ-*), driven
 * PAR→authorize→login→consent over HTTP with in-memory storage.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/index.js";
import { loadConfig } from "../../src/config.js";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";
import { MockPdp } from "../../src/authz/adapters/mock.js";
import type { PolicyDecisionPoint } from "../../src/authz/pdp.js";
import type { Storage } from "../../src/db/repositories/types.js";
import { sha256Base64Url } from "../../src/crypto/hash.js";
import {
  ASSERTION_TYPE,
  authorizeToCode,
  createTestClient,
  form,
  getSessionCookie,
  makeClientAssertion,
  seedClient,
  type TestClient,
} from "../helpers/client.js";

const config = loadConfig({ STORAGE: "memory", ISSUER: "https://as.example.com" });
const ISSUER = config.issuer;

let app: FastifyInstance;
let storage: Storage;
let client: TestClient;

class DenyPdp implements PolicyDecisionPoint {
  async evaluate() {
    return { decision: false };
  }
}
class ThrowingPdp implements PolicyDecisionPoint {
  async evaluate(): Promise<never> {
    throw new Error("pdp unreachable");
  }
}

function build(pdp?: PolicyDecisionPoint) {
  return buildApp({ config, storage, pdp: pdp ?? new MockPdp() });
}

beforeEach(async () => {
  storage = createMemoryStorage();
  client = await createTestClient();
  await seedClient(storage, client);
  app = build();
  await app.ready();
});

afterEach(async () => {
  await app.close();
});

async function push(over: Record<string, string> = {}, target = app): Promise<string> {
  const res = await target.inject({
    method: "POST",
    url: "/par",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: await makeClientAssertion(client, ISSUER),
      response_type: "code",
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: "openid",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
      state: "xyz",
      ...over,
    }),
  });
  expect(res.statusCode, res.payload).toBe(201);
  return (res.json() as { request_uri: string }).request_uri;
}

describe("GET /authorize (interaction start)", () => {
  it("redirects to the interaction (login/consent), not straight to a code", async () => {
    const requestUri = await push();
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    });
    expect(res.statusCode).toBe(303);
    expect(String(res.headers.location)).toContain("/interaction?id=");
  });

  it("completes login+consent and redirects with code, state, iss [RFC6749 §4.1.2; RFC9207 §2]", async () => {
    const requestUri = await push();
    const loc = await authorizeToCode(app, { requestUri, clientId: client.clientId });
    expect(loc.origin + loc.pathname).toBe(client.redirectUri);
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe("xyz");
    expect(loc.searchParams.get("iss")).toBe(ISSUER);
  });

  it("issues a code stored hashed, bound to the grant, ≤60s [FAPI2 5.3.2.1(11)]", async () => {
    const requestUri = await push();
    const loc = await authorizeToCode(app, { requestUri, clientId: client.clientId });
    const code = loc.searchParams.get("code")!;
    const now = new Date();
    const redeemed = await storage.codes.redeem(sha256Base64Url(code), now);
    expect(redeemed.status).toBe("ok");
    if (redeemed.status === "ok") {
      expect(redeemed.record.clientId).toBe(client.clientId);
      expect(redeemed.record.redirectUri).toBe(client.redirectUri);
      expect(redeemed.record.expiresAt.getTime() - now.getTime()).toBeLessThanOrEqual(60_000);
    }
  });

  it("consumes the request_uri at consent (one-time use) [RFC9126 §4 / FAPI2-AUTHZ-15]", async () => {
    const requestUri = await push();
    await authorizeToCode(app, { requestUri, clientId: client.clientId });
    // The request_uri is now consumed; starting a new authorize with it fails.
    const again = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    });
    expect(again.statusCode).toBe(400);
    expect((again.json() as { error: string }).error).toBe("invalid_request");
  });

  it("redirects access_denied (state, iss) when the user denies consent [OIDC §3.1.2.6]", async () => {
    const requestUri = await push();
    const loc = await authorizeToCode(app, { requestUri, clientId: client.clientId, approve: false });
    expect(loc.searchParams.get("error")).toBe("access_denied");
    expect(loc.searchParams.get("state")).toBe("xyz");
    expect(loc.searchParams.get("iss")).toBe(ISSUER);
    expect(loc.searchParams.get("code")).toBeNull();
  });

  it("carries the request nonce into the issued code", async () => {
    const requestUri = await push({ nonce: "n-0S6_WzA2Mj" });
    const loc = await authorizeToCode(app, { requestUri, clientId: client.clientId });
    const redeemed = await storage.codes.redeem(sha256Base64Url(loc.searchParams.get("code")!), new Date());
    if (redeemed.status === "ok") expect(redeemed.record.nonce).toBe("n-0S6_WzA2Mj");
  });
});

describe("GET /authorize error handling", () => {
  it("rejects a non-PAR request (request_uri required) [FAPI2 5.3.2.2(3)]", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/authorize?response_type=code&client_id=${client.clientId}&redirect_uri=${encodeURIComponent(client.redirectUri)}&scope=openid&code_challenge=abc&code_challenge_method=S256`,
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_request");
  });

  it("does NOT redirect on an invalid request_uri (untrusted target) [OIDC-10]", async () => {
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=urn:ietf:params:oauth:request_uri:bogus`,
    });
    expect(res.statusCode).toBe(400);
    expect(res.headers.location).toBeUndefined();
  });

  it("rejects a client_id that does not match the pushed request [RFC9126 §2.2]", async () => {
    const requestUri = await push();
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=someone-else&request_uri=${encodeURIComponent(requestUri)}`,
    });
    expect(res.statusCode).toBe(400);
  });

  it("rejects repeated client_id/request_uri parameters [RFC6749 §3.1]", async () => {
    const requestUri = await push();
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&client_id=other&request_uri=${encodeURIComponent(requestUri)}`,
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_request");
  });
});

describe("GET /authorize prompt=none (non-interactive)", () => {
  it("redirects login_required when there is no session [OIDC §3.1.2.6]", async () => {
    const requestUri = await push({ prompt: "none" });
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    });
    expect(res.statusCode).toBe(303);
    const loc = new URL(String(res.headers.location));
    expect(loc.searchParams.get("error")).toBe("login_required");
    expect(loc.searchParams.get("iss")).toBe(ISSUER);
  });

  it("issues a code without UI when already authenticated and the PDP allows", async () => {
    const cookie = await getSessionCookie(app, { requestUri: await push(), clientId: client.clientId });
    const requestUri = await push({ prompt: "none" });
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
      headers: { cookie },
    });
    expect(res.statusCode).toBe(303);
    expect(new URL(String(res.headers.location)).searchParams.get("code")).toBeTruthy();
  });

  it("redirects interaction_required when authenticated but the PDP denies", async () => {
    const denyApp = build(new DenyPdp());
    await denyApp.ready();
    try {
      const cookie = await getSessionCookie(denyApp, { requestUri: await push({}, denyApp), clientId: client.clientId });
      const requestUri = await push({ prompt: "none" }, denyApp);
      const res = await denyApp.inject({
        method: "GET",
        url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
        headers: { cookie },
      });
      expect(res.statusCode).toBe(303);
      expect(new URL(String(res.headers.location)).searchParams.get("error")).toBe("interaction_required");
    } finally {
      await denyApp.close();
    }
  });
});

describe("consent decision via PDP", () => {
  it("fails closed (access_denied) when the PDP throws", async () => {
    const errApp = build(new ThrowingPdp());
    await errApp.ready();
    try {
      const requestUri = await push({}, errApp);
      const loc = await authorizeToCode(errApp, { requestUri, clientId: client.clientId });
      expect(loc.searchParams.get("error")).toBe("access_denied");
      expect(loc.searchParams.get("code")).toBeNull();
    } finally {
      await errApp.close();
    }
  });
});
