import type { FastifyInstance } from "fastify";
import type { AppConfig } from "../config.js";
import type { PolicyDecisionPoint } from "../authz/pdp.js";
import type { Storage } from "../db/repositories/types.js";
import type { KeyStore } from "../crypto/keys.js";
import { OAuthError } from "../domain/errors.js";
import { registerDiscovery } from "./discovery.js";
import { registerFormBodyParser } from "./form.js";
import { registerPar } from "./par.js";
import { registerAuthorize } from "./authorize.js";
import { registerToken } from "./token.js";
import { registerRevoke } from "./revoke.js";
import { registerIntrospect } from "./introspect.js";
import { registerUserinfo } from "./userinfo.js";
import { FixedWindowRateLimiter } from "./rate-limit.js";

export interface EndpointDeps {
  config: AppConfig;
  pdp: PolicyDecisionPoint;
  storage: Storage;
  keystore: KeyStore;
  /** Shared across the credential-bearing endpoints so RATE_LIMIT_PER_MIN is
   * one per-source budget, not one per endpoint. */
  rateLimiter: FixedWindowRateLimiter;
}

/**
 * Protocol engine boundary: each endpoint is a thin handler delegating to
 * scratch-implemented protocol logic in src/domain.
 *   GET  /.well-known/openid-configuration   OIDC Discovery §4
 *   GET  /.well-known/oauth-authorization-server   RFC 8414 §3
 *   GET  /jwks                                RFC 7517
 *   POST /par                                 RFC 9126           (P1-b)
 *   GET|POST /authorize                       RFC 6749 + PKCE    (P1-c)
 *   POST /token                               private_key_jwt + DPoP (P1-d)
 *   POST /revoke                              RFC 7009           (P1-e)
 *   POST /introspect                          RFC 7662           (P1-e)
 */
export type EndpointDepsInput = Omit<EndpointDeps, "rateLimiter">;

export function registerEndpoints(app: FastifyInstance, input: EndpointDepsInput): void {
  const deps: EndpointDeps = {
    ...input,
    rateLimiter: new FixedWindowRateLimiter(input.config.rateLimitPerMin),
  };
  // Central OAuth error mapping (RFC 6749 §5.2): endpoints throw OAuthError;
  // this handler renders status/headers/JSON body consistently, including
  // WWW-Authenticate (invalid_client) and DPoP-Nonce (use_dpop_nonce).
  app.setErrorHandler((err, req, reply) => {
    if (err instanceof OAuthError) {
      // Audit the rejection server-side (never leaked to the client beyond the
      // spec error body).
      req.log.info(
        { audit: "oauth_error", url: req.url, error: err.error, error_description: err.description },
        "oauth error",
      );
      void reply
        .headers({ "cache-control": "no-store", pragma: "no-cache", ...err.headers })
        .code(err.status)
        .send(err.toBody());
      return;
    }
    // Framework errors with a meaningful 4xx (e.g. 413 body-too-large at the
    // PAR endpoint, RFC 9126 §2.3) keep their status but get a FIXED
    // description — raw framework messages can quote request content and
    // fingerprint the stack. Everything else is an opaque server_error.
    const { statusCode } = err as { statusCode?: unknown };
    const status = typeof statusCode === "number" ? statusCode : 500;
    if (status >= 400 && status < 500) {
      const description =
        status === 413 ? "request entity too large" :
        status === 415 ? "unsupported media type" :
        "malformed request";
      req.log.info({ err }, "request rejected");
      void reply
        .headers({ "cache-control": "no-store", pragma: "no-cache" })
        .code(status)
        .send({ error: "invalid_request", error_description: description });
      return;
    }
    req.log.error({ err }, "unhandled error");
    void reply
      .headers({ "cache-control": "no-store", pragma: "no-cache" })
      .code(500)
      .send({ error: "server_error" });
  });

  registerFormBodyParser(app);
  registerDiscovery(app, deps);
  registerPar(app, deps);
  registerAuthorize(app, deps);
  registerToken(app, deps);
  registerRevoke(app, deps);
  registerIntrospect(app, deps);
  registerUserinfo(app, deps);
}
