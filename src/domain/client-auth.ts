/**
 * private_key_jwt client authentication (RFC 7521 §4.2 / RFC 7523 §2.2, §3;
 * OIDC Core §9), hardened per FAPI2 5.3.2.1(8)(13). Used identically by the
 * token, PAR, revocation, and introspection endpoints (RFC 9126 §2).
 *
 * Every assertion failure maps to invalid_client (RFC 7523 §3.2 / PKJWT-11)
 * with a single uniform description to limit client enumeration; only mixing
 * multiple authentication mechanisms is invalid_request (RFC 6749 §5.2). A
 * JWKS fetch outage is NOT a bad credential and surfaces as 5xx.
 *
 * Order: the subject is read UNVERIFIED only to locate the client and its
 * keys; every claim is then validated against the signature-verified payload
 * returned by verifyJws.
 */
import type { AppConfig } from "../config.js";
import type { Storage } from "../db/repositories/types.js";
import {
  clientKeyResolver,
  verifyJws,
  JwksUnavailableError,
  JwsVerificationError,
} from "../crypto/jws.js";
import { invalidClient, invalidRequest, OAuthError } from "./errors.js";
import {
  loadClient,
  clientJwksSource,
  InvalidClientMetadataError,
  type Client,
} from "./clients.js";

export const CLIENT_ASSERTION_TYPE_JWT_BEARER =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** Uniform failure message (specifics stay in server logs, not on the wire). */
const AUTH_FAILED = "client authentication failed";

export interface ClientAuthInput {
  /** Parsed form body (duplicate params arrive as arrays and are rejected). */
  body: Record<string, unknown>;
  /** Authorization request header, to detect mixed auth mechanisms. */
  authorizationHeader?: string;
}

/** RFC 6749 §3.1: parameters sent without a value are treated as omitted. */
const present = (v: unknown): boolean => v !== undefined && v !== "";
const single = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;

/**
 * Authenticate the client from a token-endpoint-style request.
 * Throws OAuthError; returns the authenticated Client.
 */
export async function authenticateClient(
  input: ClientAuthInput,
  deps: { storage: Storage; config: AppConfig; now?: Date },
): Promise<Client> {
  const now = deps.now ?? new Date();
  const body = input.body;

  // RFC 7521 §4.2.1 / RFC 6749 §2.3: more than one authentication mechanism
  // in one request is an error.
  const assertionPresent =
    present(body.client_assertion) || present(body.client_assertion_type);
  const mechanisms = [
    assertionPresent,
    present(body.client_secret),
    present(input.authorizationHeader),
  ].filter(Boolean).length;
  if (mechanisms > 1) {
    throw invalidRequest("multiple client authentication mechanisms used [RFC7521 §4.2.1]");
  }
  if (present(body.client_secret) || present(input.authorizationHeader)) {
    // FAPI2-GEN-6: private_key_jwt only.
    throw invalidClient("unsupported client authentication method [FAPI2 5.3.2.1(6)]");
  }

  // Duplicate parameters (arrays) are malformed (RFC 6749 §3.2).
  if (
    Array.isArray(body.client_assertion) ||
    Array.isArray(body.client_assertion_type) ||
    Array.isArray(body.client_id)
  ) {
    throw invalidRequest("request parameters must not be repeated [RFC6749 §3.2]");
  }
  const assertionStr = single(body.client_assertion);
  const typeStr = single(body.client_assertion_type);
  if (!assertionStr || !typeStr) {
    throw invalidClient("client authentication required (private_key_jwt) [FAPI2 5.3.2.2(4)]");
  }
  if (typeStr !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
    throw invalidClient("unsupported client_assertion_type [RFC7523 §2.2]");
  }
  // RFC 7523 §2.2: the parameter MUST NOT contain more than one JWT.
  if (assertionStr.split(".").length !== 3 || /[\s,]/.test(assertionStr)) {
    throw invalidClient(AUTH_FAILED);
  }

  // Read the subject UNVERIFIED, solely to locate the client and its keys;
  // trust is established by the signature check below, after which every
  // claim is re-read from the verified payload.
  const subjectHint = decodeSubjectHint(assertionStr);
  let client: Client | null = null;
  try {
    client = subjectHint ? await loadClient(deps.storage.clients, subjectHint) : null;
  } catch (err) {
    // A malformed registration row is a misconfiguration, not a client error,
    // but must not become a 500 storm — the client simply cannot authenticate.
    if (err instanceof InvalidClientMetadataError) throw invalidClient(AUTH_FAILED);
    throw err;
  }
  if (!client) {
    throw invalidClient(AUTH_FAILED);
  }

  // RFC 7523 §3(9): signature against the client's registered keys.
  let claims: Record<string, unknown>;
  try {
    ({ payload: claims } = await verifyJws(
      assertionStr,
      clientKeyResolver(clientJwksSource(client)),
    ));
  } catch (err) {
    if (err instanceof JwksUnavailableError) {
      // Registered key material is unreachable — a server-side outage, not a
      // bad credential (do not tell the client to rotate keys).
      throw new OAuthError("server_error", "client key set is temporarily unavailable", {
        status: 503,
      });
    }
    if (err instanceof JwsVerificationError) {
      throw invalidClient(AUTH_FAILED);
    }
    throw err;
  }

  // RFC 7523 §3(1)(2) + RFC 7521 §6.1: iss and sub MUST both be the client_id.
  if (claims.sub !== client.clientId || claims.iss !== client.clientId) {
    throw invalidClient(AUTH_FAILED);
  }
  // RFC 7521 §4.2: an accompanying client_id must identify the same client.
  const clientIdParam = single(body.client_id);
  if (clientIdParam !== undefined && clientIdParam !== client.clientId) {
    throw invalidClient(AUTH_FAILED);
  }

  // FAPI2 5.3.2.1(8): only the issuer identifier, as a string, is an
  // acceptable audience (RFC 7523's token-endpoint-URL option is rejected,
  // and so are arrays).
  if (claims.aud !== deps.config.issuer) {
    throw invalidClient("client assertion aud must be the issuer identifier string [FAPI2 5.3.2.1(8)]");
  }

  // RFC 7523 §3(4): exp REQUIRED; reject expired and unreasonably distant.
  const nowSec = Math.floor(now.getTime() / 1000);
  const skew = deps.config.clockSkewFutureAcceptSec;
  const exp = claims.exp;
  if (typeof exp !== "number") {
    throw invalidClient("client assertion exp is required [RFC7523 §3(4)]");
  }
  if (exp <= nowSec) {
    throw invalidClient("client assertion has expired [RFC7523 §3(4)]");
  }
  if (exp - nowSec > deps.config.clientAssertionMaxLifetimeSec) {
    throw invalidClient("client assertion exp is unreasonably far in the future [RFC7523 §3(4)]");
  }
  // FAPI2 5.3.2.1(13): iat/nbf up to `skew` seconds in the future are
  // accepted; anything beyond is rejected (hard cap 60s enforced by config).
  for (const claim of ["iat", "nbf"] as const) {
    const v = claims[claim];
    if (v !== undefined) {
      if (typeof v !== "number") throw invalidClient(`client assertion ${claim} must be a number`);
      if (v > nowSec + skew) {
        throw invalidClient(`client assertion ${claim} is in the future [FAPI2 5.3.2.1(13)]`);
      }
    }
  }

  // OIDC Core §9: jti REQUIRED for private_key_jwt; single use within exp
  // (PKJWT-8). Registered only after full validation so the guard cannot be
  // polluted by unauthenticated garbage. The context is shared across
  // PAR/token/revocation/introspection, so one assertion is usable once at
  // exactly one endpoint.
  const jti = claims.jti;
  if (typeof jti !== "string" || jti.length === 0) {
    throw invalidClient("client assertion jti is required [OIDC Core §9]");
  }
  const fresh = await deps.storage.jti.register(
    "client-assertion",
    replayId(client.clientId, jti),
    new Date(exp * 1000),
    now,
  );
  if (!fresh) {
    throw invalidClient("client assertion jti has already been used [RFC7523 §3(7)]");
  }

  return client;
}

/**
 * Unambiguous, NUL-free replay id for a (client_id, jti) pair. Both parts are
 * attacker-influenced and may contain any printable character, and the value
 * is stored in a PostgreSQL text column (which forbids NUL), so each part is
 * base64url-encoded before joining.
 */
function replayId(clientId: string, jti: string): string {
  const enc = (s: string) => Buffer.from(s, "utf8").toString("base64url");
  return `${enc(clientId)}.${enc(jti)}`;
}

/** Best-effort unverified sub extraction (client lookup only). */
function decodeSubjectHint(assertion: string): string | undefined {
  try {
    const payload = JSON.parse(
      Buffer.from(assertion.split(".")[1] ?? "", "base64url").toString("utf8"),
    ) as unknown;
    if (payload !== null && typeof payload === "object") {
      const sub = (payload as Record<string, unknown>).sub;
      if (typeof sub === "string" && sub.length > 0) return sub;
    }
  } catch {
    // fall through — treated as unknown client by the caller
  }
  return undefined;
}

export type { OAuthError };
