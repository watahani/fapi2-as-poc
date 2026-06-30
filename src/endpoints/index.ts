import type { FastifyInstance } from "fastify";
import type pg from "pg";
import type { AppConfig } from "../config.js";
import type { PolicyDecisionPoint } from "../authz/pdp.js";

export interface EndpointDeps {
  config: AppConfig;
  pdp: PolicyDecisionPoint;
  pool: pg.Pool;
}

/**
 * Protocol engine boundary. P1 registers the FAPI 2.0 endpoints here, each a
 * thin handler delegating to scratch-implemented protocol logic in src/domain:
 *   POST /par                              (RFC 9126)
 *   GET  /authorize                        (RFC 6749 + PKCE, PAR-required)
 *   POST /token                            (private_key_jwt + DPoP)
 *   GET  /.well-known/openid-configuration (RFC 8414 / OIDC Discovery)
 *   GET  /jwks
 */
export function registerEndpoints(_app: FastifyInstance, _deps: EndpointDeps): void {
  // no-op in P0
}
