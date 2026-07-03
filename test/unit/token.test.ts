/**
 * Token endpoint E2E (docs/REQUIREMENTS-P1.md OAUTH-*, PKJWT-*, DPOP-*,
 * JWTAT-*, OIDC-11/12): PAR → authorize → token, plus DPoP, PKCE, code
 * replay, and refresh, over HTTP with in-memory storage.
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { decodeJwt, decodeProtectedHeader } from "jose";
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
  type DpopKey,
  type TestClient,
} from "../helpers/client.js";

const config = loadConfig({ STORAGE: "memory", ISSUER: "https://as.example.com" });
const ISSUER = config.issuer;
const TOKEN_URL = `${ISSUER}/token`;
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // S256(VERIFIER)

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

afterAll(async () => {
  if (app) await app.close();
});

async function auth() {
  return {
    client_assertion_type: ASSERTION_TYPE,
    client_assertion: await makeClientAssertion(client, ISSUER),
  };
}

/** Run PAR → authorize and return the authorization code. */
async function getCode(over: Record<string, string> = {}, dpopJkt?: string): Promise<string> {
  const par = await app.inject({
    method: "POST",
    url: "/par",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({
      ...(await auth()),
      response_type: "code",
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: "openid",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      ...(dpopJkt ? { dpop_jkt: dpopJkt } : {}),
      ...over,
    }),
  });
  expect(par.statusCode, par.payload).toBe(201);
  const { request_uri } = par.json() as { request_uri: string };
  const authz = await app.inject({
    method: "GET",
    url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(request_uri)}`,
  });
  expect(authz.statusCode).toBe(303);
  return new URL(String(authz.headers.location)).searchParams.get("code")!;
}

async function token(
  params: Record<string, string>,
  opts: { dpop?: DpopKey; noAuth?: boolean; noDpop?: boolean } = {},
) {
  const dpop = opts.dpop ?? (await createDpopKey());
  const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded" };
  if (!opts.noDpop) headers.dpop = await dpop.proof({ htm: "POST", htu: TOKEN_URL });
  const base = opts.noAuth ? {} : await auth();
  return app.inject({ method: "POST", url: "/token", headers, payload: form({ ...base, ...params }) });
}

describe("POST /token — authorization_code grant", () => {
  it("issues a DPoP-bound at+jwt access token + id_token [RFC9068, RFC9449 §6.1, OIDC §3.1.3.3]", async () => {
    const dpop = await createDpopKey();
    const code = await getCode({}, dpop.jkt);
    const res = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { dpop },
    );
    expect(res.statusCode, res.payload).toBe(200);
    expect(res.headers["cache-control"]).toContain("no-store");
    const b = res.json() as Record<string, string>;
    expect(b.token_type).toBe("DPoP");
    expect(typeof b.access_token).toBe("string");
    expect(b.refresh_token).toBeTruthy();
    expect(b.id_token).toBeTruthy();

    const header = decodeProtectedHeader(b.access_token);
    expect(header.typ).toBe("at+jwt");
    expect(header.alg).toBe("ES256");
    const at = decodeJwt(b.access_token) as Record<string, unknown>;
    expect(at.iss).toBe(ISSUER);
    expect(at.aud).toBe(config.accessTokenAudience);
    expect(at.client_id).toBe(client.clientId);
    expect(at.jti).toBeTruthy();
    expect((at.cnf as { jkt: string }).jkt).toBe(dpop.jkt);

    const idt = decodeJwt(b.id_token!) as Record<string, unknown>;
    expect(idt.iss).toBe(ISSUER);
    expect(idt.aud).toBe(client.clientId);
    expect(idt.sub).toBe(config.devInteractionSub);
  });

  it("echoes the request nonce into the id_token [OIDC-2]", async () => {
    const dpop = await createDpopKey();
    const code = await getCode({ nonce: "n-abc" }, dpop.jkt);
    const res = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { dpop },
    );
    const idt = decodeJwt((res.json() as { id_token: string }).id_token);
    expect(idt.nonce).toBe("n-abc");
  });

  it("requires client authentication [RFC6749 §3.2.1; FAPI2 5.3.2.1(3)]", async () => {
    const code = await getCode();
    const res = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { noAuth: true },
    );
    expect(res.statusCode).toBe(401);
    expect((res.json() as { error: string }).error).toBe("invalid_client");
  });

  it("rejects the prohibited password grant [FAPI2 5.3.2.1(2)]", async () => {
    const res = await token({ grant_type: "password", username: "u", password: "p" }, { noAuth: true });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect((res.json() as { error: string }).error).toBe("unsupported_grant_type");
  });

  it("requires a DPoP proof [RFC9449 §5]", async () => {
    const code = await getCode();
    const res = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { noDpop: true },
    );
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_dpop_proof");
  });

  it("rejects a wrong PKCE verifier [RFC7636 §4.6]", async () => {
    const code = await getCode();
    const res = await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: client.redirectUri,
      code_verifier: "A".repeat(43),
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("rejects a mismatched redirect_uri [RFC6749 §4.1.3]", async () => {
    const code = await getCode();
    const res = await token({
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://client.example.com/other",
      code_verifier: VERIFIER,
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("enforces dpop_jkt binding from the authorization request [RFC9449 §10]", async () => {
    const boundKey = await createDpopKey();
    const code = await getCode({}, boundKey.jkt);
    // Redeem with a DIFFERENT DPoP key than the one bound at PAR.
    const res = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { dpop: await createDpopKey() },
    );
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_grant");
  });

  it("is single-use and revokes the grant's tokens on replay [RFC6749 §10.5]", async () => {
    const dpop = await createDpopKey();
    const code = await getCode({}, dpop.jkt);
    const first = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { dpop },
    );
    expect(first.statusCode).toBe(200);
    const firstJti = (decodeJwt((first.json() as { access_token: string }).access_token) as { jti: string }).jti;

    const replay = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { dpop },
    );
    expect(replay.statusCode).toBe(400);
    expect((replay.json() as { error: string }).error).toBe("invalid_grant");
    // The originally issued access token was revoked.
    expect((await storage.accessTokens.findByJti(firstJti))?.revokedAt).not.toBeNull();
  });

  it("rejects DPoP proof replay (jti reuse) [RFC9449 §11.1]", async () => {
    const dpop = await createDpopKey();
    const proof = await dpop.proof({ htm: "POST", htu: TOKEN_URL });
    const code1 = await getCode({}, dpop.jkt);
    const ok = await app.inject({
      method: "POST",
      url: "/token",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: proof },
      payload: form({ ...(await auth()), grant_type: "authorization_code", code: code1, redirect_uri: client.redirectUri, code_verifier: VERIFIER }),
    });
    expect(ok.statusCode).toBe(200);
    const code2 = await getCode({}, dpop.jkt);
    const reuse = await app.inject({
      method: "POST",
      url: "/token",
      headers: { "content-type": "application/x-www-form-urlencoded", dpop: proof },
      payload: form({ ...(await auth()), grant_type: "authorization_code", code: code2, redirect_uri: client.redirectUri, code_verifier: VERIFIER }),
    });
    expect(reuse.statusCode).toBe(400);
    expect((reuse.json() as { error: string }).error).toBe("invalid_dpop_proof");
  });

  it("rejects a DPoP proof with the wrong htu [RFC9449 §4.3]", async () => {
    const dpop = await createDpopKey();
    const code = await getCode({}, dpop.jkt);
    const res = await app.inject({
      method: "POST",
      url: "/token",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        dpop: await dpop.proof({ htm: "POST", htu: "https://as.example.com/wrong" }),
      },
      payload: form({ ...(await auth()), grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER }),
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_dpop_proof");
  });
});

describe("POST /token — refresh_token grant", () => {
  async function getRefreshToken(): Promise<{ refreshToken: string; dpop: DpopKey }> {
    const dpop = await createDpopKey();
    const code = await getCode({}, dpop.jkt);
    const res = await token(
      { grant_type: "authorization_code", code, redirect_uri: client.redirectUri, code_verifier: VERIFIER },
      { dpop },
    );
    return { refreshToken: (res.json() as { refresh_token: string }).refresh_token, dpop };
  }

  it("issues a fresh access token without rotating the refresh token [FAPI2 5.3.2.1(9)]", async () => {
    const { refreshToken } = await getRefreshToken();
    const res = await token({ grant_type: "refresh_token", refresh_token: refreshToken });
    expect(res.statusCode, res.payload).toBe(200);
    const b = res.json() as Record<string, string>;
    expect(b.access_token).toBeTruthy();
    expect(b.token_type).toBe("DPoP");
    // No rotation: the same refresh token is returned.
    expect(b.refresh_token).toBe(refreshToken);
  });

  it("binds the refreshed access token to the DPoP key presented at refresh", async () => {
    const { refreshToken } = await getRefreshToken();
    const refreshDpop = await createDpopKey();
    const res = await token({ grant_type: "refresh_token", refresh_token: refreshToken }, { dpop: refreshDpop });
    const at = decodeJwt((res.json() as { access_token: string }).access_token) as Record<string, unknown>;
    expect((at.cnf as { jkt: string }).jkt).toBe(refreshDpop.jkt);
  });

  it("rejects scope broadening [RFC6749 §6]", async () => {
    const { refreshToken } = await getRefreshToken();
    const res = await token({ grant_type: "refresh_token", refresh_token: refreshToken, scope: "openid admin" });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_scope");
  });

  it("rejects an unknown refresh token [RFC6749 §6]", async () => {
    const res = await token({ grant_type: "refresh_token", refresh_token: "nope" });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe("invalid_grant");
  });
});
