/**
 * Scratch-implemented OAuth/OIDC/FAPI protocol logic (no external OAuth lib).
 * Source of Trust = RFC / FAPI specs (docs/REQUIREMENTS-P1.md). Modules:
 *   - errors       RFC 6749 §5.2 / §4.1.2.1 error model
 *   - clients      client model + redirect_uri matching        (P1-b)
 *   - client-auth  private_key_jwt assertion checks (RFC 7523) (P1-b)
 *   - par          request_uri issuance + store (RFC 9126)     (P1-b)
 *   - pkce         S256 verification (RFC 7636)                (P1-c)
 *   - authorize    authorization request processing            (P1-c)
 *   - dpop         proof verification, jkt, nonce (RFC 9449)   (P1-d)
 *   - grant        code/refresh redemption                     (P1-d)
 *   - tokens       JWT AT (RFC 9068) + ID Token + RT           (P1-d)
 */
export * from "./errors.js";
