/**
 * JWS verification primitives on top of jose. Signature/key concerns only —
 * every protocol-level claim check (iss/sub/aud/exp/jti/replay) lives in
 * src/domain (docs/ARCHITECTURE.md separation).
 */
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type JWTPayload,
  type JSONWebKeySet,
} from "jose";

/** FAPI2 5.4.1: PS256 / ES256 / EdDSA only; `none` and MACs never verify. */
export const FAPI2_JWS_ALGS = ["ES256", "PS256", "EdDSA"] as const;

export interface VerifiedJws {
  payload: JWTPayload;
  header: { alg?: string; kid?: string; typ?: string };
}

/** The presented JWT did not verify against the key set (a bad credential). */
export class JwsVerificationError extends Error {}
/** The key set itself could not be obtained (a server-side outage, NOT a bad
 * credential — callers should surface 5xx, not invalid_client). */
export class JwksUnavailableError extends Error {}

type KeyResolver = ReturnType<typeof createLocalJWKSet>;

// createRemoteJWKSet caches + rate-limits fetches internally; keep one
// resolver per URL so those caches are effective across requests. Bounded
// (LRU by insertion order) so churned/attacker registrations can't grow it
// without limit within the memory budget.
const REMOTE_JWKS_CACHE_MAX = 1024;
const remoteJwksCache = new Map<string, KeyResolver>();

export function clientKeyResolver(client: {
  jwks?: JSONWebKeySet;
  jwksUri?: string;
}): KeyResolver {
  if (client.jwks) return createLocalJWKSet(client.jwks);
  if (client.jwksUri) {
    let resolver = remoteJwksCache.get(client.jwksUri);
    if (!resolver) {
      resolver = createRemoteJWKSet(new URL(client.jwksUri), {
        cooldownDuration: 30_000,
        cacheMaxAge: 300_000,
      }) as unknown as KeyResolver;
      if (remoteJwksCache.size >= REMOTE_JWKS_CACHE_MAX) {
        const oldest = remoteJwksCache.keys().next().value;
        if (oldest !== undefined) remoteJwksCache.delete(oldest);
      }
      remoteJwksCache.set(client.jwksUri, resolver);
    }
    return resolver;
  }
  throw new JwsVerificationError("client has no registered JWKS (jwks or jwks_uri)");
}

/**
 * Distinguish "couldn't fetch the key set" (outage → 5xx) from "the JWT is
 * bad" (invalid credential). ERR_JWKS_NO_MATCHING_KEY / signature mismatch are
 * credential failures; a fetch timeout or a network/HTTP error is an outage.
 */
function isJwksUnavailable(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  if (code === "ERR_JWKS_TIMEOUT") return true;
  // jose lets non-JOSE fetch errors (TypeError from fetch, HTTP errors)
  // propagate without a JOSE `code`; treat those as unavailability.
  return typeof code !== "string" || !code.startsWith("ERR_JW");
}

/**
 * Verify a compact JWS against a key resolver, restricted to FAPI2 algs
 * (rejects `none`/HS* by construction). Claim validation is left OFF here
 * (clockTolerance etc. are domain decisions).
 */
export async function verifyJws(
  token: string,
  keys: KeyResolver,
  opts: { typ?: string } = {},
): Promise<VerifiedJws> {
  let header;
  try {
    header = decodeProtectedHeader(token);
  } catch {
    throw new JwsVerificationError("malformed JWT");
  }
  if (!header.alg || !(FAPI2_JWS_ALGS as readonly string[]).includes(header.alg)) {
    throw new JwsVerificationError(`JWS alg not allowed: ${String(header.alg)} [FAPI2 5.4.1]`);
  }
  try {
    const { payload, protectedHeader } = await jwtVerify(token, keys, {
      algorithms: [...FAPI2_JWS_ALGS],
      ...(opts.typ ? { typ: opts.typ } : {}),
      // Claims are validated in src/domain with the profile's skew rules
      // (large-but-sane tolerance disables jose's exp/nbf check without
      // risking numeric overflow in epoch arithmetic).
      clockTolerance: 10 ** 10,
    });
    return { payload, header: protectedHeader };
  } catch (err) {
    if (err instanceof JwsVerificationError) throw err;
    if (isJwksUnavailable(err)) {
      throw new JwksUnavailableError(`key set unavailable: ${(err as Error).name}`);
    }
    throw new JwsVerificationError(`JWS verification failed: ${(err as Error).name}`);
  }
}
