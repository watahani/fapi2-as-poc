/**
 * Grant + authorization code issuance and redemption (RFC 6749 §4.1).
 *
 * A grant records one authorization (subject + client + scope + auth context)
 * and everything issued from it, so replay/revocation operate per grant
 * (OAUTH-5 / NFR-3). Authorization codes are stored hashed, single-use, bound
 * to the client and redirect_uri, ≤60s lifetime (FAPI2 5.3.2.1(11)).
 */
import { randomBytes, randomUUID } from "node:crypto";
import type { AppConfig } from "../config.js";
import type {
  AuthorizationCodeRecord,
  GrantRecord,
  Storage,
} from "../db/repositories/types.js";
import { sha256Base64Url } from "../crypto/hash.js";
import { invalidGrant } from "./errors.js";
import { verifyS256 } from "./pkce.js";
import type { ValidatedAuthorizationRequest } from "./authz-request.js";
import type { AuthenticatedUser } from "./interaction.js";

export interface IssuedCode {
  code: string;
  grantId: string;
}

/**
 * Create the grant and a fresh authorization code for it. Returns the raw
 * code (only the hash is persisted).
 */
export async function issueAuthorizationCode(
  input: {
    client: { clientId: string };
    user: AuthenticatedUser;
    request: ValidatedAuthorizationRequest;
  },
  deps: { storage: Storage; config: AppConfig; now?: Date },
): Promise<IssuedCode> {
  const now = deps.now ?? new Date();
  const grantId = randomUUID();
  await deps.storage.grants.insert({
    grantId,
    clientId: input.client.clientId,
    subject: input.user.sub,
    scope: input.request.scope,
    authTime: input.user.authTime,
    createdAt: now,
    revokedAt: null,
  });

  // 256-bit opaque code; stored by SHA-256 hash (OAUTH-12).
  const code = randomBytes(32).toString("base64url");
  await deps.storage.codes.insert({
    codeHash: sha256Base64Url(code),
    grantId,
    clientId: input.client.clientId,
    redirectUri: input.request.redirectUri,
    codeChallenge: input.request.codeChallenge,
    codeChallengeMethod: input.request.codeChallengeMethod,
    dpopJkt: input.request.dpopJkt ?? null,
    nonce: input.request.nonce ?? null,
    expiresAt: new Date(now.getTime() + deps.config.authCodeTtlSec * 1000),
  });

  return { code, grantId };
}

export interface RedeemedCode {
  record: AuthorizationCodeRecord;
  grant: GrantRecord;
}

/**
 * Redeem an authorization code at the token endpoint (RFC 6749 §4.1.3 + PKCE
 * RFC 7636 §4.6 + DPoP RFC 9449 §10). Enforces single use with replay-driven
 * grant revocation (OAUTH-5 / §10.5), client binding, redirect_uri equality,
 * PKCE S256, and dpop_jkt↔proof-key binding. Throws invalid_grant on failure.
 */
export async function redeemAuthorizationCode(
  input: {
    code: string;
    clientId: string;
    redirectUri?: string;
    codeVerifier?: string;
    /** JWK thumbprint from the presented DPoP proof (DPOP-13 binding). */
    dpopJkt: string;
  },
  deps: { storage: Storage; now?: Date },
): Promise<RedeemedCode> {
  const now = deps.now ?? new Date();
  const result = await deps.storage.codes.redeem(sha256Base64Url(input.code), now);

  if (result.status === "consumed") {
    // Code reuse: revoke every token minted from that grant (RFC 6749 §10.5).
    const grantId = result.record.grantId;
    await deps.storage.grants.revoke(grantId, now);
    await deps.storage.accessTokens.revokeByGrant(grantId, now);
    await deps.storage.refreshTokens.revokeByGrant(grantId, now);
    throw invalidGrant("authorization code has already been used [RFC6749 §4.1.2]");
  }
  if (result.status === "invalid") {
    throw invalidGrant("authorization code is invalid or expired [RFC6749 §4.1.2]");
  }

  const record = result.record;
  // RFC 6749 §4.1.3: the code was issued to this authenticated client.
  if (record.clientId !== input.clientId) {
    throw invalidGrant("authorization code was issued to a different client [RFC6749 §4.1.3]");
  }
  // §4.1.3: redirect_uri was present in the authorization request, so it is
  // REQUIRED here and must be identical.
  if (input.redirectUri !== record.redirectUri) {
    throw invalidGrant("redirect_uri does not match the authorization request [RFC6749 §4.1.3]");
  }
  // RFC 7636 §4.6: verify the PKCE code_verifier (S256).
  if (!input.codeVerifier || !verifyS256(input.codeVerifier, record.codeChallenge)) {
    throw invalidGrant("PKCE verification failed [RFC7636 §4.6]");
  }
  // RFC 9449 §10 / DPOP-13: if the code was bound to a DPoP key, the proof key
  // presented now must match.
  if (record.dpopJkt && record.dpopJkt !== input.dpopJkt) {
    throw invalidGrant("DPoP key does not match the authorization request [RFC9449 §10]");
  }

  const grant = await deps.storage.grants.find(record.grantId);
  if (!grant || grant.revokedAt !== null) {
    throw invalidGrant("grant is no longer valid");
  }
  return { record, grant };
}

/** Validate a refresh token for the refresh_token grant (RFC 6749 §6). */
export async function loadRefreshGrant(
  input: { refreshToken: string; clientId: string },
  deps: { storage: Storage; now?: Date },
): Promise<{ grant: GrantRecord; scope: string }> {
  const now = deps.now ?? new Date();
  const rec = await deps.storage.refreshTokens.findByHash(sha256Base64Url(input.refreshToken));
  if (!rec || rec.revokedAt !== null || rec.expiresAt.getTime() <= now.getTime()) {
    throw invalidGrant("refresh token is invalid or expired [RFC6749 §6]");
  }
  // §6: the refresh token was issued to this authenticated client.
  if (rec.clientId !== input.clientId) {
    throw invalidGrant("refresh token was issued to a different client [RFC6749 §6]");
  }
  const grant = await deps.storage.grants.find(rec.grantId);
  if (!grant || grant.revokedAt !== null) {
    throw invalidGrant("grant is no longer valid");
  }
  return { grant, scope: rec.scope };
}
