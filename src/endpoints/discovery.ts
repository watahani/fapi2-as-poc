/**
 * Discovery / AS metadata + JWKS endpoints.
 *
 * OIDC Discovery §4: {issuer}/.well-known/openid-configuration (suffix
 * APPENDED after the issuer path). RFC 8414 §3: /.well-known/
 * oauth-authorization-server INSERTED between host and issuer path. Both
 * documents are served with identical values (RFC 9068 §4 consistency).
 */
import type { FastifyInstance } from "fastify";
import type { AppConfig } from "../config.js";
import { endpointPaths, endpointUrls } from "../config.js";
import type { KeyStore } from "../crypto/keys.js";

/** FAPI2-CRYPTO-2: PS256 / ES256 / EdDSA only; the AS itself signs ES256. */
const ACCEPTED_JWS_ALGS = ["ES256", "PS256", "EdDSA"] as const;

export function buildMetadata(config: AppConfig): Record<string, unknown> {
  const urls = endpointUrls(config);
  return {
    // DISC-3 / RFC 8414 §2: issuer identical to the discovery URL prefix.
    issuer: config.issuer,
    authorization_endpoint: urls.authorization,
    token_endpoint: urls.token,
    jwks_uri: urls.jwks,
    userinfo_endpoint: urls.userinfo,
    pushed_authorization_request_endpoint: urls.par,
    revocation_endpoint: urls.revocation,
    introspection_endpoint: urls.introspection,
    // FAPI2-AUTHZ-1: authorization code flow only.
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    // OIDC-15: public subject identifiers.
    subject_types_supported: ["public"],
    scopes_supported: ["openid", "profile"],
    claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce"],
    // DISC-8: ES256 only — deliberate FAPI2 deviation from OIDD's RS256 MUST
    // (docs/REQUIREMENTS-P1.md §14).
    id_token_signing_alg_values_supported: ["ES256"],
    // FAPI2-GEN-6: private_key_jwt (mTLS is out of scope until P5).
    token_endpoint_auth_methods_supported: ["private_key_jwt"],
    token_endpoint_auth_signing_alg_values_supported: [...ACCEPTED_JWS_ALGS],
    revocation_endpoint_auth_methods_supported: ["private_key_jwt"],
    revocation_endpoint_auth_signing_alg_values_supported: [...ACCEPTED_JWS_ALGS],
    introspection_endpoint_auth_methods_supported: ["private_key_jwt"],
    introspection_endpoint_auth_signing_alg_values_supported: [...ACCEPTED_JWS_ALGS],
    // PKCE-9 / FAPI2-AUTHZ-5: S256 only.
    code_challenge_methods_supported: ["S256"],
    // PAR-13 / FAPI2-AUTHZ-3: PAR is the only way in.
    require_pushed_authorization_requests: true,
    // ISS-3 / RFC 9207 §3.
    authorization_response_iss_parameter_supported: true,
    // DPOP-18 / RFC 9449 §5.1.
    dpop_signing_alg_values_supported: [...ACCEPTED_JWS_ALGS],
  };
}

/** Well-known paths derived from the issuer (DISC-1 append / DISC-2 insert). */
export function wellKnownPaths(issuer: string): { oidc: string; oauth: string } {
  const issuerPath = new URL(issuer).pathname.replace(/\/$/, "");
  return {
    oidc: `${issuerPath}/.well-known/openid-configuration`,
    oauth: `/.well-known/oauth-authorization-server${issuerPath}`,
  };
}

export function registerDiscovery(
  app: FastifyInstance,
  deps: { config: AppConfig; keystore: KeyStore },
): void {
  const metadata = buildMetadata(deps.config);
  const paths = wellKnownPaths(deps.config.issuer);

  const serve = async () => metadata;
  app.get(paths.oidc, serve);
  if (paths.oauth !== paths.oidc) app.get(paths.oauth, serve);

  // JWKS (RFC 7517): public keys only, each with a kid (FAPI2 5.4.2 / DISC-7).
  // Route paths come from endpointPaths so registration and the advertised
  // metadata URLs provably agree.
  app.get(endpointPaths(deps.config).jwks, async () => {
    await deps.keystore.ensure();
    return deps.keystore.publicJwks();
  });
}
