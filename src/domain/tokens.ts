/**
 * Token construction: JWT access tokens (RFC 9068), OIDC ID Tokens, and opaque
 * refresh tokens. Signing is delegated to the ES256 keystore; this module owns
 * the claim sets and the persistence needed for introspection/revocation.
 */
import { randomBytes, randomUUID } from "node:crypto";
import type { AppConfig } from "../config.js";
import type { KeyStore } from "../crypto/keys.js";
import { sha256Base64Url } from "../crypto/hash.js";
import type { Storage } from "../db/repositories/types.js";
import type { AuthenticatedUser } from "./interaction.js";

export interface TokenIssuanceInput {
  grantId: string;
  clientId: string;
  subject: string;
  scope: string;
  /** cnf.jkt for DPoP sender-constraining (RFC 9449 §6.1). */
  cnfJkt: string;
  authTime?: Date;
  acr?: string;
  amr?: string[];
  nonce?: string | null;
}

/** RFC 6749 §5.1 wire shape (snake_case) — sent as the token response body. */
export interface IssuedTokens {
  access_token: string;
  token_type: "DPoP";
  expires_in: number;
  scope: string;
  refresh_token?: string;
  id_token?: string;
}

/** RFC 9068 JWT access token: typ=at+jwt, cnf.jkt, all required claims. */
export async function issueAccessToken(
  input: TokenIssuanceInput,
  deps: { storage: Storage; keystore: KeyStore; config: AppConfig; now?: Date },
): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const now = deps.now ?? new Date();
  const nowSec = Math.floor(now.getTime() / 1000);
  const jti = randomUUID();
  const expiresAt = new Date(now.getTime() + deps.config.accessTokenTtlSec * 1000);

  const token = await deps.keystore.signJwt(
    {
      iss: deps.config.issuer,
      aud: deps.config.accessTokenAudience,
      sub: input.subject,
      client_id: input.clientId,
      iat: nowSec,
      exp: Math.floor(expiresAt.getTime() / 1000),
      jti,
      scope: input.scope,
      cnf: { jkt: input.cnfJkt },
    },
    { typ: "at+jwt" },
  );

  await deps.storage.accessTokens.insert({
    jti,
    grantId: input.grantId,
    clientId: input.clientId,
    subject: input.subject,
    scope: input.scope,
    cnfJkt: input.cnfJkt,
    expiresAt,
    revokedAt: null,
  });

  return { token, jti, expiresAt };
}

/** OIDC Core §2 ID Token (ES256; typ default JWT). */
export async function issueIdToken(
  input: {
    clientId: string;
    subject: string;
    authTime?: Date;
    acr?: string;
    amr?: string[];
    nonce?: string | null;
  },
  deps: { keystore: KeyStore; config: AppConfig; now?: Date },
): Promise<string> {
  const now = deps.now ?? new Date();
  const nowSec = Math.floor(now.getTime() / 1000);
  const claims: Record<string, unknown> = {
    iss: deps.config.issuer,
    sub: input.subject,
    aud: input.clientId,
    iat: nowSec,
    exp: nowSec + deps.config.idTokenTtlSec,
  };
  // OIDC-2: echo the request nonce verbatim when present.
  if (input.nonce) claims.nonce = input.nonce;
  if (input.authTime) claims.auth_time = Math.floor(input.authTime.getTime() / 1000);
  if (input.acr) claims.acr = input.acr;
  if (input.amr) claims.amr = input.amr;
  return deps.keystore.signJwt(claims);
}

/** Opaque refresh token (RFC 6749 §6); stored by SHA-256 hash, no rotation
 * (FAPI2 5.3.2.1(9)) — bound to the client via client authentication. */
export async function issueRefreshToken(
  input: { grantId: string; clientId: string; scope: string },
  deps: { storage: Storage; config: AppConfig; now?: Date },
): Promise<string> {
  const now = deps.now ?? new Date();
  const token = randomBytes(32).toString("base64url");
  await deps.storage.refreshTokens.insert({
    tokenHash: sha256Base64Url(token),
    grantId: input.grantId,
    clientId: input.clientId,
    scope: input.scope,
    expiresAt: new Date(now.getTime() + deps.config.refreshTokenTtlSec * 1000),
    revokedAt: null,
  });
  return token;
}

/** Convenience: the full token response for a grant. */
export async function issueTokenSet(
  input: TokenIssuanceInput & { openid: boolean; withRefreshToken: boolean },
  deps: { storage: Storage; keystore: KeyStore; config: AppConfig; now?: Date },
): Promise<IssuedTokens> {
  const at = await issueAccessToken(input, deps);
  const result: IssuedTokens = {
    access_token: at.token,
    token_type: "DPoP",
    expires_in: deps.config.accessTokenTtlSec,
    scope: input.scope,
  };
  if (input.openid) {
    result.id_token = await issueIdToken(
      {
        clientId: input.clientId,
        subject: input.subject,
        authTime: input.authTime,
        acr: input.acr,
        amr: input.amr,
        nonce: input.nonce,
      },
      deps,
    );
  }
  if (input.withRefreshToken) {
    result.refresh_token = await issueRefreshToken(
      { grantId: input.grantId, clientId: input.clientId, scope: input.scope },
      deps,
    );
  }
  return result;
}

export type { AuthenticatedUser };
