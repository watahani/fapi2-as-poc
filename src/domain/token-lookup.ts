/**
 * Resolve a presented token (JWT access token or opaque refresh token) to its
 * stored record, for the revocation (RFC 7009) and introspection (RFC 7662)
 * endpoints. Access tokens are self-contained JWTs (RFC 9068): the signature
 * and issuer are verified before the jti is trusted for lookup; refresh tokens
 * are opaque and found by SHA-256 hash.
 */
import { createLocalJWKSet, jwtVerify } from "jose";
import type { AppConfig } from "../config.js";
import type { KeyStore } from "../crypto/keys.js";
import { sha256Base64Url } from "../crypto/hash.js";
import type {
  AccessTokenRecord,
  RefreshTokenRecord,
  Storage,
} from "../db/repositories/types.js";

export type ResolvedToken =
  | { kind: "access_token"; record: AccessTokenRecord }
  | { kind: "refresh_token"; record: RefreshTokenRecord };

export interface LookupDeps {
  storage: Storage;
  keystore: KeyStore;
  config: AppConfig;
}

export async function findAccessToken(token: string, deps: LookupDeps): Promise<ResolvedToken | null> {
  await deps.keystore.ensure();
  let jti: string;
  try {
    const jwks = createLocalJWKSet(deps.keystore.publicJwks() as never);
    const { payload } = await jwtVerify(token, jwks, {
      issuer: deps.config.issuer,
      typ: "at+jwt",
      // exp is evaluated by the caller against the stored record / claims.
      clockTolerance: 10 ** 10,
    });
    if (typeof payload.jti !== "string") return null;
    jti = payload.jti;
  } catch {
    return null; // not one of our signed access tokens
  }
  const record = await deps.storage.accessTokens.findByJti(jti);
  return record ? { kind: "access_token", record } : null;
}

async function findRefreshToken(token: string, deps: LookupDeps): Promise<ResolvedToken | null> {
  const record = await deps.storage.refreshTokens.findByHash(sha256Base64Url(token));
  return record ? { kind: "refresh_token", record } : null;
}

/**
 * Resolve a token, honouring token_type_hint but falling back to the other
 * type if the hint misses (RFC 7009 §2.1 / RFC 7662 §2.1).
 */
export async function resolveToken(
  token: string,
  hint: string | undefined,
  deps: LookupDeps,
): Promise<ResolvedToken | null> {
  const order =
    hint === "refresh_token"
      ? [findRefreshToken, findAccessToken]
      : [findAccessToken, findRefreshToken];
  for (const find of order) {
    const found = await find(token, deps);
    if (found) return found;
  }
  return null;
}
