/**
 * Authentication + authorization-decision boundary (docs/ARCHITECTURE.md
 * separations 1 and 2).
 *
 * P1 ships a DEV interaction: the configured test subject is auto-authenticated
 * (no login UI), and the consent/authorization decision is delegated to the
 * PDP (AuthZEN) so the AS stays a PEP. P2 replaces authenticateUser with
 * external IdP delegation; the PDP call is unchanged.
 */
import type { AppConfig } from "../config.js";
import type { PolicyDecisionPoint } from "../authz/pdp.js";
import type { Client } from "./clients.js";
import type { ValidatedAuthorizationRequest } from "./authz-request.js";

export interface AuthenticatedUser {
  sub: string;
  authTime: Date;
  acr?: string;
  amr?: string[];
}

export interface AuthenticationResult {
  ok: boolean;
  user?: AuthenticatedUser;
  /** OIDC error when authentication cannot be satisfied (e.g. prompt=none). */
  error?: "login_required" | "interaction_required";
}

/**
 * P1 dev authentication: auto-authenticate the configured subject with no UI.
 * Because there is never a login interaction, prompt=none is satisfiable and
 * prompt=login re-auth is trivially "just happened" (authTime=now), so this
 * always succeeds. The AuthenticationResult error path exists for P2, where an
 * external IdP replaces this and prompt=none with no session returns
 * login_required and max_age is enforced against the real auth_time.
 */
export function authenticateUser(
  request: ValidatedAuthorizationRequest,
  config: AppConfig,
  now: Date = new Date(),
): AuthenticationResult {
  void request;
  return {
    ok: true,
    user: { sub: config.devInteractionSub, authTime: now, acr: "urn:dev:auto", amr: ["dev"] },
  };
}

/**
 * Consent / authorization decision via the PDP (AS acts as PEP). Returns
 * whether the release of an authorization code to the client is permitted.
 */
export async function decideAuthorization(
  pdp: PolicyDecisionPoint,
  input: { user: AuthenticatedUser; client: Client; request: ValidatedAuthorizationRequest },
): Promise<{ allowed: boolean }> {
  const decision = await pdp.evaluate({
    subject: { type: "user", id: input.user.sub },
    action: { name: "oauth.authorize" },
    resource: { type: "oauth_client", id: input.client.clientId },
    context: {
      scope: input.request.scope,
      redirect_uri: input.request.redirectUri,
      acr: input.user.acr,
    },
  });
  return { allowed: decision.decision };
}
