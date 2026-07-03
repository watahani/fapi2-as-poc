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
