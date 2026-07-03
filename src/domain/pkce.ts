/**
 * PKCE S256 verification (RFC 7636 §4.6). The authorization-endpoint-side
 * checks (challenge present, method S256, well-formed) live in
 * authz-request.ts; this is the token-endpoint verifier (used in P1-d).
 */
import { sha256Base64Url } from "../crypto/hash.js";

/** RFC 7636 §4.1: 43–128 unreserved characters. */
const CODE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * True iff `verifier` matches `challenge` under S256
 * (challenge == BASE64URL(SHA256(ASCII(verifier)))). Malformed verifiers
 * (wrong charset/length) never match.
 */
export function verifyS256(verifier: string, challenge: string): boolean {
  if (!CODE_VERIFIER.test(verifier)) return false;
  // Constant-work compare is unnecessary: the challenge is not a secret and
  // the verifier is checked structurally first.
  return sha256Base64Url(verifier) === challenge;
}
