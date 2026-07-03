/**
 * Hashing helpers used to store single-use / bearer secrets by digest rather
 * than in the clear (authorization codes, refresh tokens): OAUTH-12 / RFC 6749
 * §10.4. SHA-256 is also the PKCE S256 transform (RFC 7636 §4.2) and the DPoP
 * ath/jkt hash (RFC 9449).
 */
import { createHash } from "node:crypto";

/** base64url(SHA-256(utf8(value))), no padding. */
export function sha256Base64Url(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("base64url");
}
