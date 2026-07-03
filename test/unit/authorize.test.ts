/**
 * Authorization endpoint (docs/REQUIREMENTS-P1.md OIDC-*, ISS-*, PAR-10/11,
 * FAPI2-AUTHZ-*), driven PAR→authorize over HTTP with in-memory storage.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
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
  createTestClient,
  form,
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

beforeAll(async () => {
  storage = createMemoryStorage();
  client = await createTestClient();
  await seedClient(storage, client);
  app = build();
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

/** Push a request and return its request_uri. */
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

const locationOf = (res: { headers: Record<string, unknown> }) =>
  new URL(String(res.headers.location));

describe("GET /authorize", () => {
  it("redirects (303) to the redirect_uri with code, state and iss [RFC6749 §4.1.2; RFC9207 §2]", async () => {
    const requestUri = await push();
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    });
    expect(res.statusCode).toBe(303);
    const loc = locationOf(res);
    expect(loc.origin + loc.pathname).toBe(client.redirectUri);
    expect(loc.searchParams.get("code")).toBeTruthy();
    expect(loc.searchParams.get("state")).toBe("xyz");
    expect(loc.searchParams.get("iss")).toBe(ISSUER);
  });

  it("issues a code stored hashed, bound to the grant, ≤60s [FAPI2 5.3.2.1(11)]", async () => {
    const requestUri = await push();
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    });
    const code = locationOf(res).searchParams.get("code")!;
    const now = new Date();
    const redeemed = await storage.codes.redeem(sha256Base64Url(code), now);
    expect(redeemed.status).toBe("ok");
    if (redeemed.status === "ok") {
      expect(redeemed.record.clientId).toBe(client.clientId);
      expect(redeemed.record.redirectUri).toBe(client.redirectUri);
      const ttlMs = redeemed.record.expiresAt.getTime() - now.getTime();
      expect(ttlMs).toBeLessThanOrEqual(60_000);
    }
  });

  it("consumes the request_uri (one-time use) [RFC9126 §4 / FAPI2-AUTHZ-15]", async () => {
    const requestUri = await push();
    const url = `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`;
    expect((await app.inject({ method: "GET", url })).statusCode).toBe(303);
    // Second use of the same request_uri fails (cannot redirect → 400 page).
    const second = await app.inject({ method: "GET", url });
    expect(second.statusCode).toBe(400);
    expect((second.json() as { error: string }).error).toBe("invalid_request");
  });

  it("also supports POST [OIDC §3.1.2.1]", async () => {
    const requestUri = await push();
    const res = await app.inject({
      method: "POST",
      url: "/authorize",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ client_id: client.clientId, request_uri: requestUri }),
    });
    expect(res.statusCode).toBe(303);
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

  it("redirects access_denied (with state, iss) when the PDP denies consent [OIDC §3.1.2.6]", async () => {
    const denyApp = build(new DenyPdp());
    await denyApp.ready();
    try {
      const requestUri = await push({}, denyApp);
      const res = await denyApp.inject({
        method: "GET",
        url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
      });
      expect(res.statusCode).toBe(303);
      const loc = locationOf(res);
      expect(loc.searchParams.get("error")).toBe("access_denied");
      expect(loc.searchParams.get("state")).toBe("xyz");
      expect(loc.searchParams.get("iss")).toBe(ISSUER);
      expect(loc.searchParams.get("code")).toBeNull();
    } finally {
      await denyApp.close();
    }
  });

  it("never uses HTTP 307 for the redirect [FAPI2 5.3.2.2(10)]", async () => {
    const requestUri = await push();
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    });
    expect(res.statusCode).not.toBe(307);
    expect(res.statusCode).toBe(303);
  });

  it("fails closed (no code) when the PDP throws [PDP fail-closed]", async () => {
    const errApp = build(new ThrowingPdp());
    await errApp.ready();
    try {
      const requestUri = await push({}, errApp);
      const res = await errApp.inject({
        method: "GET",
        url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
      });
      // Either an access_denied redirect or a 5xx — never a code.
      if (res.statusCode === 303) {
        expect(locationOf(res).searchParams.get("code")).toBeNull();
      } else {
        expect(res.statusCode).toBeGreaterThanOrEqual(500);
      }
    } finally {
      await errApp.close();
    }
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

  it("replaces a pre-registered iss/state in the redirect_uri, not append [RFC9207 mix-up]", async () => {
    const tricky = await createTestClient({ redirectUri: "https://cb.example.com/cb?iss=https://evil.example" });
    await seedClient(storage, tricky);
    const trickyClient = client;
    client = tricky;
    try {
      const requestUri = await push();
      const res = await app.inject({
        method: "GET",
        url: `/authorize?client_id=${tricky.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
      });
      expect(res.statusCode).toBe(303);
      const loc = locationOf(res);
      // Exactly one iss, and it is the AS issuer (not the attacker's).
      expect(loc.searchParams.getAll("iss")).toEqual([ISSUER]);
    } finally {
      client = trickyClient;
    }
  });

  it("carries the nonce from the pushed request into the issued grant/code", async () => {
    const requestUri = await push({ nonce: "n-0S6_WzA2Mj" });
    const res = await app.inject({
      method: "GET",
      url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(requestUri)}`,
    });
    const code = locationOf(res).searchParams.get("code")!;
    const redeemed = await storage.codes.redeem(sha256Base64Url(code), new Date());
    if (redeemed.status === "ok") expect(redeemed.record.nonce).toBe("n-0S6_WzA2Mj");
  });
});
