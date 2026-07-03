/**
 * Revocation (RFC 7009) and introspection (RFC 7662) endpoints
 * (docs/REQUIREMENTS-P1.md REV-*, INTR-*), driven through the full
 * PAR→authorize→token flow over HTTP with in-memory storage.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/index.js";
import { loadConfig } from "../../src/config.js";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";
import type { Storage } from "../../src/db/repositories/types.js";
import {
  ASSERTION_TYPE,
  createDpopKey,
  createTestClient,
  form,
  makeClientAssertion,
  seedClient,
  type TestClient,
} from "../helpers/client.js";

const config = loadConfig({ STORAGE: "memory", ISSUER: "https://as.example.com" });
const ISSUER = config.issuer;
const TOKEN_URL = `${ISSUER}/token`;
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

let app: FastifyInstance;
let storage: Storage;
let client: TestClient;

beforeEach(async () => {
  storage = createMemoryStorage();
  client = await createTestClient();
  await seedClient(storage, client);
  app = buildApp({ config, storage });
  await app.ready();
});

afterEach(async () => {
  await app.close();
});

async function authOf(c: TestClient) {
  return { client_assertion_type: ASSERTION_TYPE, client_assertion: await makeClientAssertion(c, ISSUER) };
}

/** Full flow → { access_token, refresh_token }. */
async function issueTokens(): Promise<{ accessToken: string; refreshToken: string }> {
  const dpop = await createDpopKey();
  const par = await app.inject({
    method: "POST",
    url: "/par",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({
      ...(await authOf(client)),
      response_type: "code",
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: "openid",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      dpop_jkt: dpop.jkt,
    }),
  });
  const { request_uri } = par.json() as { request_uri: string };
  const authz = await app.inject({
    method: "GET",
    url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(request_uri)}`,
  });
  const code = new URL(String(authz.headers.location)).searchParams.get("code")!;
  const tok = await app.inject({
    method: "POST",
    url: "/token",
    headers: { "content-type": "application/x-www-form-urlencoded", dpop: await dpop.proof({ htm: "POST", htu: TOKEN_URL }) },
    payload: form({ ...(await authOf(client)), grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER }),
  });
  const b = tok.json() as { access_token: string; refresh_token: string };
  return { accessToken: b.access_token, refreshToken: b.refresh_token };
}

function introspect(token: string, c = client, hint?: string) {
  return authOf(c).then((auth) =>
    app.inject({
      method: "POST",
      url: "/introspect",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ ...auth, token, ...(hint ? { token_type_hint: hint } : {}) }),
    }),
  );
}

function revoke(token: string, c = client, hint?: string) {
  return authOf(c).then((auth) =>
    app.inject({
      method: "POST",
      url: "/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ ...auth, token, ...(hint ? { token_type_hint: hint } : {}) }),
    }),
  );
}

describe("POST /introspect (RFC 7662)", () => {
  it("reports an active access token with its claims + cnf.jkt [INTR-4]", async () => {
    const { accessToken } = await issueTokens();
    const res = await introspect(accessToken);
    expect(res.statusCode).toBe(200);
    const b = res.json() as Record<string, unknown>;
    expect(b.active).toBe(true);
    expect(b.token_type).toBe("DPoP");
    expect(b.client_id).toBe(client.clientId);
    expect(b.sub).toBe(config.devInteractionSub);
    expect((b.cnf as { jkt: string }).jkt).toBeTruthy();
  });

  it("reports an active refresh token", async () => {
    const { refreshToken } = await issueTokens();
    const b = (await introspect(refreshToken)).json() as Record<string, unknown>;
    expect(b.active).toBe(true);
    expect(b.token_type).toBe("refresh_token");
  });

  it("returns active:false for an unknown token [INTR-2/3]", async () => {
    const b = (await introspect("not-a-token")).json() as { active: boolean };
    expect(b.active).toBe(false);
  });

  it("returns active:false for another client's token (no disclosure) [INTR-1]", async () => {
    const { accessToken } = await issueTokens();
    const other = await createTestClient({ clientId: "other-client" });
    await seedClient(storage, other);
    const b = (await introspect(accessToken, other)).json() as { active: boolean };
    expect(b.active).toBe(false);
  });

  it("requires client authentication [RFC7662 §2.1]", async () => {
    const { accessToken } = await issueTokens();
    const res = await app.inject({
      method: "POST",
      url: "/introspect",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ token: accessToken }),
    });
    expect(res.statusCode).toBe(401);
  });
});

describe("POST /revoke (RFC 7009)", () => {
  it("revokes a refresh token and cascades to its access tokens [REV-1/REV-5]", async () => {
    const { accessToken, refreshToken } = await issueTokens();
    expect((await revoke(refreshToken)).statusCode).toBe(200);
    // Both the refresh token and the grant's access token are now inactive.
    expect(((await introspect(refreshToken)).json() as { active: boolean }).active).toBe(false);
    expect(((await introspect(accessToken)).json() as { active: boolean }).active).toBe(false);
  });

  it("revokes an access token [REV-1]", async () => {
    const { accessToken } = await issueTokens();
    expect((await revoke(accessToken, client, "access_token")).statusCode).toBe(200);
    expect(((await introspect(accessToken)).json() as { active: boolean }).active).toBe(false);
  });

  it("returns 200 for an unknown token [REV-4]", async () => {
    expect((await revoke("nope")).statusCode).toBe(200);
  });

  it("does not revoke another client's token [REV-3]", async () => {
    const { accessToken } = await issueTokens();
    const other = await createTestClient({ clientId: "other-client-2" });
    await seedClient(storage, other);
    expect((await revoke(accessToken, other)).statusCode).toBe(200); // no oracle
    // The token is still active for its real owner.
    expect(((await introspect(accessToken)).json() as { active: boolean }).active).toBe(true);
  });

  it("ignores an unrecognised token_type_hint and still revokes [RFC7009 §2.1 / REV-2]", async () => {
    const { accessToken } = await issueTokens();
    // A bogus hint must be ignored (search all types), not rejected.
    expect((await revoke(accessToken, client, "bogus_type")).statusCode).toBe(200);
    expect(((await introspect(accessToken)).json() as { active: boolean }).active).toBe(false);
  });

  it("requires client authentication [RFC7009 §2.1]", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/revoke",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ token: "x" }),
    });
    expect(res.statusCode).toBe(401);
  });
});
