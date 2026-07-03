/**
 * Authorization endpoint (RFC 6749 §3.1, OIDC Core §3.1.2, FAPI2 5.3.2.2).
 *
 * PAR is mandatory (FAPI2-AUTHZ-3): the only accepted request carries a
 * request_uri obtained from /par. The endpoint consumes it (one-time use at
 * authorization action — RFC 9126 §4 / FAPI2-AUTHZ-15), authenticates the
 * user (dev interaction in P1), gets the PDP consent decision, issues an
 * authorization code, and redirects (303) with code + state + iss (RFC 9207).
 *
 * Redirect vs error page (OIDC-10): only once a client + registered
 * redirect_uri are trusted (i.e. the request_uri was valid) may errors be
 * delivered by redirect; before that, errors are shown directly and never
 * sent to an unvalidated URI.
 */
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
import { AuthorizeError, OAuthError, type AuthorizeErrorCode } from "../domain/errors.js";
import { issueAuthorizationCode } from "../domain/grant.js";
import { authenticateUser, decideAuthorization } from "../domain/interaction.js";
import type { EndpointDeps } from "./index.js";

/** Map an OAuthError code raised by shared validation onto a redirect-legal
 * authorization error code (RFC 6749 §4.1.2.1 / OIDC §3.1.2.6). */
function toAuthorizeCode(code: string): AuthorizeErrorCode {
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

export function registerAuthorize(app: FastifyInstance, deps: EndpointDeps): void {
  const path = endpointPaths(deps.config).authorization;
  const iss = deps.config.issuer;

  // RFC 6749 §3.1: the authorization endpoint MUST support GET and MAY
  // support POST (OIDC Core §3.1.2.1 makes POST a MUST).
  const handler = async (req: FastifyRequest, reply: FastifyReply) => {
    const params = readParams(req);
    return handleAuthorize(params, reply, deps, iss);
  };
  app.get(path, handler);
  app.post(path, handler);
}

/** Single-value query/body accessor (repeated params rejected). */
function readParams(req: FastifyRequest): Record<string, unknown> {
  const source =
    req.method === "POST"
      ? ((req.body ?? {}) as Record<string, unknown>)
      : ((req.query ?? {}) as Record<string, unknown>);
  return source;
}

async function handleAuthorize(
  params: Record<string, unknown>,
  reply: FastifyReply,
  deps: EndpointDeps,
  iss: string,
): Promise<FastifyReply> {
  // RFC 6749 §3.1 / OAUTH-1: parameters MUST NOT be repeated. Arrays here
  // mean a polluted query/body — reject explicitly (str() would otherwise
  // read them as missing).
  if (Array.isArray(params.client_id) || Array.isArray(params.request_uri)) {
    return errorPage(reply, "invalid_request", "request parameters must not be repeated [RFC6749 §3.1]");
  }
  const clientId = str(params.client_id);
  const requestUri = str(params.request_uri);

  // Pre-redirect validation: without a trusted client + redirect_uri we must
  // NOT redirect (OIDC-10 / RFC 6749 §4.1.2.1). FAPI2-AUTHZ-3: PAR required.
  if (!requestUri) {
    return errorPage(reply, "invalid_request", "PAR is required: request_uri missing [FAPI2 5.3.2.2(3)]");
  }
  if (!clientId) {
    return errorPage(reply, "invalid_request", "client_id is required [RFC6749 §3.1]");
  }

  // One-time-use consumption at the authorization action (RFC 9126 §4).
  const pushed = await deps.storage.par.consume(requestUri, new Date());
  if (!pushed) {
    return errorPage(reply, "invalid_request", "request_uri is invalid, expired, or already used [RFC9126 §4]");
  }
  // RFC 9126 §2.2 binding: the request_uri belongs to the pushing client.
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
  if (!client) {
    return errorPage(reply, "invalid_request", "unknown client");
  }

  // Re-validate the pushed request (RFC 9126 §4). The redirect_uri is now
  // trusted (registered + validated at PAR), so from here errors redirect.
  let request: ValidatedAuthorizationRequest;
  try {
    request = validateAuthorizationRequest(pushed.params, client, deps.config);
  } catch (err) {
    if (err instanceof OAuthError) {
      // Only redirect the error if the pushed redirect_uri is STILL registered
      // for this client (metadata may have changed since PAR); otherwise it is
      // no longer trusted and the error is shown directly (OIDC-10).
      const trusted = pushed.params.redirect_uri;
      if (!trusted || !redirectUriRegistered(client, trusted)) {
        return errorPage(reply, toAuthorizeCode(err.error), err.description ?? err.error);
      }
      return redirectError(reply, trusted, toAuthorizeCode(err.error), err.description, pushed.params.state, iss);
    }
    throw err;
  }

  // Authentication (dev interaction in P1).
  const auth = authenticateUser(request, deps.config);
  if (!auth.ok || !auth.user) {
    return redirectError(reply, request.redirectUri, auth.error ?? "login_required", "authentication could not be completed", request.state, iss);
  }

  // Consent / authorization decision (PDP; AS is PEP). Fail closed: a PDP
  // error or non-decision must never issue a code.
  let allowed = false;
  try {
    ({ allowed } = await decideAuthorization(deps.pdp, { user: auth.user, client, request }));
  } catch {
    allowed = false;
  }
  if (!allowed) {
    // prompt=none means "no interaction": a denial there is a silent-auth
    // failure the client should retry with UI, not a hard refusal
    // (OIDC §3.1.2.6).
    const promptNone = request.prompt?.split(" ").includes("none") ?? false;
    const code: AuthorizeErrorCode = promptNone ? "interaction_required" : "access_denied";
    return redirectError(reply, request.redirectUri, code, "authorization was not granted", request.state, iss);
  }

  const { code } = await issueAuthorizationCode({ client, user: auth.user, request }, deps);

  // RFC 6749 §4.1.2 + RFC 9207 §2: code, state (echoed), iss.
  const location = buildRedirect(request.redirectUri, {
    code,
    ...(request.state !== undefined ? { state: request.state } : {}),
    iss,
  });
  // FAPI2 5.3.2.2(11): use 303 (never 307 for credentialed redirects).
  return reply.header("cache-control", "no-store").redirect(location, 303);
}

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;

/** RFC 6749 §4.1.2.1: deliver an error directly (no redirect) when the
 * redirect target is not trusted. */
function errorPage(reply: FastifyReply, error: AuthorizeErrorCode, description: string): FastifyReply {
  return reply
    .header("cache-control", "no-store")
    .code(400)
    .send({ error, error_description: description });
}

function redirectError(
  reply: FastifyReply,
  redirectUri: string,
  error: AuthorizeErrorCode,
  description: string | undefined,
  state: string | undefined,
  iss: string,
): FastifyReply {
  const location = buildRedirect(redirectUri, {
    error,
    ...(description ? { error_description: description } : {}),
    ...(state !== undefined ? { state } : {}),
    iss,
  });
  return reply.header("cache-control", "no-store").redirect(location, 303);
}

/** Add response parameters to the redirect URI's query component. Any
 * pre-registered param of the same name is REPLACED, not appended, so a
 * registered `?iss=`/`?state=` cannot inject a second value that a client
 * reading the first occurrence would trust (RFC 9207 mix-up / OAUTH-4). */
function buildRedirect(redirectUri: string, params: Record<string, string>): string {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.toString();
}

// Referenced so AuthorizeError stays part of the error taxonomy (thrown by
// future interaction code paths); redirect mapping above handles its codes.
export type { AuthorizeError };
