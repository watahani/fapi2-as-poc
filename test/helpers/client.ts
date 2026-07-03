/**
 * Test fixtures: a registered confidential client with an ES256 keypair and
 * a private_key_jwt assertion factory (RFC 7523 §2.2 / OIDC Core §9).
 */
import { createHash, randomUUID } from "node:crypto";
import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type JWK,
  type KeyLike,
} from "jose";
import type { Storage } from "../../src/db/repositories/types.js";

export interface TestClient {
  clientId: string;
  privateKey: KeyLike;
  redirectUri: string;
  /** Registered (public) client record for storage seeding. */
  record: { clientId: string; clientName: string | null; metadata: Record<string, unknown> };
}

export async function createTestClient(
  overrides: { clientId?: string; scope?: string; redirectUri?: string } = {},
): Promise<TestClient> {
  const clientId = overrides.clientId ?? `test-client-${randomUUID()}`;
  const redirectUri = overrides.redirectUri ?? "https://client.example.com/cb";
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const publicJwk = await exportJWK(publicKey);
  return {
    clientId,
    privateKey,
    redirectUri,
    record: {
      clientId,
      clientName: "Test Client",
      metadata: {
        redirect_uris: [redirectUri],
        token_endpoint_auth_method: "private_key_jwt",
        jwks: { keys: [{ ...publicJwk, alg: "ES256", use: "sig" }] },
        scope: overrides.scope ?? "openid",
      },
    },
  };
}

export async function seedClient(storage: Storage, client: TestClient): Promise<void> {
  await storage.clients.upsert(client.record);
}

export interface AssertionOverrides {
  iss?: string;
  sub?: string;
  aud?: unknown;
  exp?: number;
  iat?: number;
  nbf?: number;
  jti?: string | null;
  signWith?: KeyLike;
  alg?: string;
}

/** A valid client assertion by default; override single claims to break it. */
export async function makeClientAssertion(
  client: TestClient,
  issuer: string,
  over: AssertionOverrides = {},
): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    iss: over.iss ?? client.clientId,
    sub: over.sub ?? client.clientId,
    aud: over.aud ?? issuer,
    exp: over.exp ?? nowSec + 60,
    iat: over.iat ?? nowSec,
  };
  if (over.nbf !== undefined) payload.nbf = over.nbf;
  if (over.jti !== null) payload.jti = over.jti ?? randomUUID();
  return new SignJWT(payload as never)
    .setProtectedHeader({ alg: over.alg ?? "ES256" })
    .sign(over.signWith ?? client.privateKey);
}

export const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** application/x-www-form-urlencoded body from a param map. */
export function form(params: Record<string, string | string[]>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    for (const item of Array.isArray(v) ? v : [v]) sp.append(k, item);
  }
  return sp.toString();
}

/** A DPoP proof holder: its own key pair + proof factory (RFC 9449 §4). */
export interface DpopKey {
  privateKey: KeyLike;
  publicJwk: JWK;
  jkt: string;
  proof(opts: { htm: string; htu: string } & Partial<DpopClaims>): Promise<string>;
}

interface DpopClaims {
  jti: string;
  iat: number;
  nonce: string;
  ath: string;
}

export async function createDpopKey(): Promise<DpopKey> {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = (await exportJWK(publicKey)) as JWK;
  const jkt = await calculateJwkThumbprint(publicJwk, "sha256");
  return {
    privateKey,
    publicJwk,
    jkt,
    async proof(opts) {
      const nowSec = Math.floor(Date.now() / 1000);
      const payload: Record<string, unknown> = {
        jti: opts.jti ?? randomUUID(),
        htm: opts.htm,
        htu: opts.htu,
        iat: opts.iat ?? nowSec,
      };
      if (opts.nonce !== undefined) payload.nonce = opts.nonce;
      if (opts.ath !== undefined) payload.ath = opts.ath;
      return new SignJWT(payload as never)
        .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
        .sign(privateKey);
    },
  };
}

/** RFC 9449 §6.1 ath: base64url(SHA-256(access token)). */
export function accessTokenHash(token: string): string {
  return createHash("sha256").update(token, "ascii").digest("base64url");
}

// --- Interactive authorization flow (P2) test helper ---

interface Injectable {
  inject(opts: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    payload?: string;
  }): Promise<{
    statusCode: number;
    headers: Record<string, unknown>;
    payload: string;
  }>;
}

function hidden(html: string, name: string): string {
  const m = html.match(new RegExp(`name="${name}" value="([^"]*)"`));
  if (!m) throw new Error(`hidden field ${name} not found in interaction HTML`);
  return m[1].replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&");
}

function sessionCookieValue(setCookie: unknown): string | undefined {
  const arr = Array.isArray(setCookie) ? setCookie : setCookie ? [String(setCookie)] : [];
  for (const c of arr) {
    const m = String(c).match(/(__Host-as_session=[^;]*)/);
    if (m) return m[1];
  }
  return undefined;
}

/**
 * Drive the full interactive authorization flow (GET /authorize → login →
 * consent) and return the final redirect Location. `approve=false` denies.
 */
export async function authorizeToCode(
  app: Injectable,
  opts: { requestUri: string; clientId: string; username?: string; approve?: boolean },
): Promise<URL> {
  const username = opts.username ?? "dev-user";
  const approve = opts.approve ?? true;

  const start = await app.inject({
    method: "GET",
    url: `/authorize?client_id=${encodeURIComponent(opts.clientId)}&request_uri=${encodeURIComponent(opts.requestUri)}`,
  });
  if (start.statusCode !== 303) {
    throw new Error(`authorize did not start interaction: ${start.statusCode} ${start.payload}`);
  }
  const interactionUrl = String(start.headers.location);

  // Login page.
  const loginPage = await app.inject({ method: "GET", url: interactionUrl });
  const id = hidden(loginPage.payload, "interaction_id");
  const loginRes = await app.inject({
    method: "POST",
    url: "/interaction/login",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({ interaction_id: id, csrf: hidden(loginPage.payload, "csrf"), username }),
  });
  if (loginRes.statusCode !== 303) throw new Error(`login failed: ${loginRes.statusCode} ${loginRes.payload}`);
  const cookie = sessionCookieValue(loginRes.headers["set-cookie"]);
  if (!cookie) throw new Error("no session cookie set after login");

  // Consent page (authenticated).
  const consentUrl = String(loginRes.headers.location);
  const consentPage = await app.inject({ method: "GET", url: consentUrl, headers: { cookie } });
  const consentRes = await app.inject({
    method: "POST",
    url: "/interaction/consent",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    payload: form({
      interaction_id: hidden(consentPage.payload, "interaction_id"),
      csrf: hidden(consentPage.payload, "csrf"),
      decision: approve ? "approve" : "deny",
    }),
  });
  if (consentRes.statusCode !== 303) {
    throw new Error(`consent did not redirect: ${consentRes.statusCode} ${consentRes.payload}`);
  }
  return new URL(String(consentRes.headers.location));
}

/**
 * Establish a login session (authorize → login) against a parked request and
 * return the session cookie, without completing consent. Used to test the
 * prompt=none (already-authenticated) path.
 */
export async function getSessionCookie(
  app: Injectable,
  opts: { requestUri: string; clientId: string; username?: string },
): Promise<string> {
  const username = opts.username ?? "dev-user";
  const start = await app.inject({
    method: "GET",
    url: `/authorize?client_id=${encodeURIComponent(opts.clientId)}&request_uri=${encodeURIComponent(opts.requestUri)}`,
  });
  const loginPage = await app.inject({ method: "GET", url: String(start.headers.location) });
  const loginRes = await app.inject({
    method: "POST",
    url: "/interaction/login",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({
      interaction_id: hidden(loginPage.payload, "interaction_id"),
      csrf: hidden(loginPage.payload, "csrf"),
      username,
    }),
  });
  const cookie = sessionCookieValue(loginRes.headers["set-cookie"]);
  if (!cookie) throw new Error("no session cookie");
  return cookie;
}
