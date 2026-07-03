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
import type { Storage } from "../db/repositories/types.js";
import { sha256Base64Url } from "../crypto/hash.js";
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
