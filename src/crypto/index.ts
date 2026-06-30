/**
 * Cryptographic helpers built on `jose` (the only crypto dependency).
 * Scope is signing/verification primitives only; protocol-level claim,
 * replay, and state validation live in src/domain. Populated in P1:
 *   - ES256 (P-256) signing keys + JWKS management/rotation
 *   - JWT access token / id_token construction
 *   - JWS verification for DPoP proofs and private_key_jwt assertions
 */
export {};
