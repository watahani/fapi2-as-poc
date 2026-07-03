/**
 * Authentication + authorization-decision boundary (docs/ARCHITECTURE.md
 * separations 1 and 2).
 *
 * P2 makes the authorization endpoint INTERACTIVE: the user logs in (via an
 * AuthenticationProvider) and consents before a code is issued. The default
 * provider is a dev local login; an external OIDC IdP is a drop-in adapter
 * behind the same interface (P2.5). The consent/authorization decision is
 * still delegated to the PDP (AuthZEN) so the AS stays a PEP.
 */
import type { AppConfig } from "../config.js";
import type { PolicyDecisionPoint } from "../authz/pdp.js";
import type { LoginSession } from "./sessions.js";
import type { Client } from "./clients.js";
import type { ValidatedAuthorizationRequest } from "./authz-request.js";

export interface AuthenticatedUser {
  sub: string;
  authTime: Date;
  acr?: string;
  amr?: string[];
}

/**
 * Authenticates an end-user from submitted credentials. Implementations are
 * swappable (dev local login now; external IdP later). Returns null when the
 * credentials are not accepted.
 */
export interface AuthenticationProvider {
  authenticate(credentials: { username?: string }): Promise<AuthenticatedUser | null>;
}

/**
 * Dev login: accepts a username from the configured allowlist (DEV_LOGIN_USERS,
 * defaulting to DEV_INTERACTION_SUB). No password — dev only; production
 * delegates to an external IdP (P2.5).
 */
export class DevLoginProvider implements AuthenticationProvider {
  private readonly allowed: Set<string>;
  constructor(config: AppConfig) {
    this.allowed = new Set(config.devLoginUsers);
  }
  async authenticate(credentials: { username?: string }): Promise<AuthenticatedUser | null> {
    const username = credentials.username?.trim();
    if (!username || !this.allowed.has(username)) return null;
    return { sub: username, authTime: new Date(), acr: "urn:dev:pwd", amr: ["pwd"] };
  }
}

/**
 * Whether the current login session must be re-established for this request:
 * no session, prompt=login (force reauth), or max_age exceeded (OIDC
 * §3.1.2.1). `now` in seconds since epoch.
 */
export function needsReauthentication(
  session: LoginSession | null,
  request: ValidatedAuthorizationRequest,
  nowSec: number,
): boolean {
  if (!session) return true;
  const prompts = request.prompt?.split(" ").filter(Boolean) ?? [];
  if (prompts.includes("login")) return true;
  if (request.maxAge !== undefined && nowSec - session.authTime > request.maxAge) return true;
  return false;
}

/**
 * Consent / authorization decision via the PDP (AS acts as PEP). The user's
 * interactive approve/deny is passed as context; the PDP has the final say.
 * Returns whether releasing an authorization code to the client is permitted.
 */
export async function decideAuthorization(
  pdp: PolicyDecisionPoint,
  input: {
    user: AuthenticatedUser;
    client: Client;
    request: ValidatedAuthorizationRequest;
    userApproved?: boolean;
  },
): Promise<{ allowed: boolean }> {
  // A user denial is authoritative — do not even ask the PDP.
  if (input.userApproved === false) return { allowed: false };
  const decision = await pdp.evaluate({
    subject: { type: "user", id: input.user.sub },
    action: { name: "oauth.authorize" },
    resource: { type: "oauth_client", id: input.client.clientId },
    context: {
      scope: input.request.scope,
      redirect_uri: input.request.redirectUri,
      acr: input.user.acr,
      user_approved: input.userApproved ?? null,
    },
  });
  return { allowed: decision.decision };
}
