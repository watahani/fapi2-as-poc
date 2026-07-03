/**
 * Authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2, FAPI2 5.3.2.2).
 *
 * PAR is mandatory (FAPI2-AUTHZ-3): the only accepted request carries a
 * request_uri obtained from /par. The endpoint validates it WITHOUT consuming
 * it (the request_uri is consumed at the authorization action = consent
 * approval, RFC 9126 §4 / FAPI2-AUTHZ-15), parks a pending interaction, and
 * hands off to the interactive login/consent flow (/interaction). For
 * prompt=none it decides non-interactively (no UI) and either issues a code
 * or returns login_required / interaction_required.
 *
 * Redirect vs error page (OIDC-10): only once a client + registered
 * redirect_uri are trusted (i.e. the request_uri was valid) may errors be
 * delivered by redirect; before that, errors are shown directly.
 */
import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { endpointPaths } from "../config.js";
import {
  validateAuthorizationRequest,
  type ValidatedAuthorizationRequest,
} from "../domain/authz-request.js";
import {
  loadClient,
  redirectUriRegistered,
  InvalidClientMetadataError,
  type Client,
} from "../domain/clients.js";
import { OAuthError, type AuthorizeErrorCode } from "../domain/errors.js";
import { decideAuthorization, needsReauthentication } from "../domain/interaction.js";
import { openSession, readCookie, SESSION_COOKIE } from "../domain/sessions.js";
import { issueCodeForInteraction } from "./interaction.js";
import { errorPage, redirectError } from "./redirect.js";
import type { EndpointDeps } from "./index.js";

/** Map an OAuthError code raised by shared validation onto a redirect-legal
 * authorization error code (RFC 6749 §4.1.2.1 / OIDC §3.1.2.6). */
export function toAuthorizeCode(code: string): AuthorizeErrorCode {
  switch (code) {
    case "invalid_request":
    case "unauthorized_client":
    case "access_denied":
    case "unsupported_response_type":
    case "invalid_scope":
      return code;
    default:
      return "invalid_request";
  }
}

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;

export function registerAuthorize(app: FastifyInstance, deps: EndpointDeps): void {
  const path = endpointPaths(deps.config).authorization;
  const iss = deps.config.issuer;

  // RFC 6749 §3.1: authorization endpoint MUST support GET and (OIDC) POST.
  const handler = (req: FastifyRequest, reply: FastifyReply) => {
    const source =
      req.method === "POST"
        ? ((req.body ?? {}) as Record<string, unknown>)
        : ((req.query ?? {}) as Record<string, unknown>);
    return handleAuthorize(source, req, reply, deps, iss);
  };
  app.get(path, handler);
  app.post(path, handler);
}

async function handleAuthorize(
  params: Record<string, unknown>,
  req: FastifyRequest,
  reply: FastifyReply,
  deps: EndpointDeps,
  iss: string,
): Promise<FastifyReply> {
  // RFC 6749 §3.1 / OAUTH-1: parameters MUST NOT be repeated.
  if (Array.isArray(params.client_id) || Array.isArray(params.request_uri)) {
    return errorPage(reply, "invalid_request", "request parameters must not be repeated [RFC6749 §3.1]");
  }
  const clientId = str(params.client_id);
  const requestUri = str(params.request_uri);

  // Pre-redirect validation (OIDC-10): without a trusted client + redirect_uri
  // we must NOT redirect. FAPI2-AUTHZ-3: PAR required.
  if (!requestUri) {
    return errorPage(reply, "invalid_request", "PAR is required: request_uri missing [FAPI2 5.3.2.2(3)]");
  }
  if (!clientId) {
    return errorPage(reply, "invalid_request", "client_id is required [RFC6749 §3.1]");
  }

  // Peek (do NOT consume — consumption is the authorization action).
  const pushed = await deps.storage.par.peek(requestUri, new Date());
  if (!pushed) {
    return errorPage(reply, "invalid_request", "request_uri is invalid, expired, or already used [RFC9126 §4]");
  }
  if (pushed.clientId !== clientId) {
    return errorPage(reply, "invalid_request", "client_id does not match the pushed request [RFC9126 §2.2]");
  }

  let client: Client | null;
  try {
    client = await loadClient(deps.storage.clients, clientId);
  } catch (err) {
    if (err instanceof InvalidClientMetadataError) {
      return errorPage(reply, "invalid_request", "client registration is invalid");
    }
    throw err;
  }
  if (!client) return errorPage(reply, "invalid_request", "unknown client");

  // Re-validate the pushed request (RFC 9126 §4). redirect_uri is now trusted.
  let request: ValidatedAuthorizationRequest;
  try {
    request = validateAuthorizationRequest(pushed.params, client, deps.config);
  } catch (err) {
    if (err instanceof OAuthError) {
      const trusted = pushed.params.redirect_uri;
      if (!trusted || !redirectUriRegistered(client, trusted)) {
        return errorPage(reply, toAuthorizeCode(err.error), err.description ?? err.error);
      }
      return redirectError(reply, trusted, toAuthorizeCode(err.error), err.description, pushed.params.state, iss);
    }
    throw err;
  }

  const now = new Date();
  const nowSec = Math.floor(now.getTime() / 1000);
  const session = openSession(readCookie(req.headers.cookie, SESSION_COOKIE), deps.config.sessionSecret, nowSec);
  const promptNone = request.prompt?.split(" ").includes("none") ?? false;

  // prompt=none: no UI. Must already be authenticated (and fresh) and the
  // authorization must be grantable without interaction (OIDC §3.1.2.3/.6).
  if (promptNone) {
    if (needsReauthentication(session, request, nowSec) || !session) {
      return redirectError(reply, request.redirectUri, "login_required", "authentication required", request.state, iss);
    }
    const user = { sub: session.sub, authTime: new Date(session.authTime * 1000), acr: session.acr, amr: session.amr };
    let allowed = false;
    try {
      ({ allowed } = await decideAuthorization(deps.pdp, { user, client, request }));
    } catch {
      allowed = false;
    }
    if (!allowed) {
      // One-time use (RFC 9126 §4): a request_uri that could not be satisfied
      // silently must not be replayable.
      await deps.storage.par.consume(requestUri, new Date());
      return redirectError(reply, request.redirectUri, "interaction_required", "consent required", request.state, iss);
    }
    return issueCodeForInteraction(reply, { requestUri, client, request, user }, deps, iss);
  }

  // Interactive: park the request and hand off to the login/consent flow.
  const id = randomUUID();
  await deps.storage.interactions.insert({
    id,
    clientId: client.clientId,
    requestUri,
    subject: null,
    authTime: null,
    acr: null,
    amr: null,
    createdAt: now,
    expiresAt: new Date(now.getTime() + deps.config.interactionTtlSec * 1000),
  });
  // 303 to the interaction dispatcher (renders login or consent).
  return reply
    .header("cache-control", "no-store")
    .redirect(`${endpointPaths(deps.config).interaction}?id=${encodeURIComponent(id)}`, 303);
}
