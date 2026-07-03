/**
 * Interactive login + consent (P2). The authorization endpoint parks a pending
 * interaction and redirects here; the user authenticates (Authentication
 * provider) and approves/denies. On approval the PDP decision is taken, the
 * PAR request_uri is consumed (the authorization action — RFC 9126 §4 /
 * FAPI2-AUTHZ-15), and a code is issued; on denial an access_denied error is
 * returned to the client (OIDC §3.1.2.6). CSRF-protected (bound to the
 * interaction id) and clickjacking-protected (global headers).
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { endpointPaths } from "../config.js";
import type { AppConfig } from "../config.js";
import { loadClient, type Client } from "../domain/clients.js";
import {
  validateAuthorizationRequest,
  type ValidatedAuthorizationRequest,
} from "../domain/authz-request.js";
import { issueAuthorizationCode } from "../domain/grant.js";
import {
  decideAuthorization,
  needsReauthentication,
  type AuthenticatedUser,
} from "../domain/interaction.js";
import { invalidGrant } from "../domain/errors.js";
import {
  issueCsrfToken,
  newSessionId,
  openSession,
  readCookie,
  sealSession,
  sessionCookie,
  verifyCsrfToken,
  SESSION_COOKIE,
  type LoginSession,
} from "../domain/sessions.js";
import { renderConsent, renderError, renderLogin } from "./views.js";
import { consentCsp, redirectCode, redirectError } from "./redirect.js";
import type { EndpointDeps } from "./index.js";

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;

function html(reply: FastifyReply, status: number, body: string): FastifyReply {
  return reply.header("content-type", "text/html; charset=utf-8").header("cache-control", "no-store").code(status).send(body);
}

function sessionFrom(req: FastifyRequest, config: AppConfig): LoginSession | null {
  return openSession(readCookie(req.headers.cookie, SESSION_COOKIE), config.sessionSecret, Math.floor(Date.now() / 1000));
}

/** Re-validate the parked request against current client metadata. */
async function loadInteractionContext(
  id: string,
  deps: EndpointDeps,
  now: Date,
): Promise<
  | {
      ok: true;
      client: Client;
      request: ValidatedAuthorizationRequest;
      requestUri: string;
      subject: string | null;
    }
  | { ok: false }
> {
  const interaction = await deps.storage.interactions.find(id, now);
  if (!interaction) return { ok: false };
  const pushed = await deps.storage.par.peek(interaction.requestUri, now);
  if (!pushed || pushed.clientId !== interaction.clientId) return { ok: false };
  const client = await loadClient(deps.storage.clients, interaction.clientId).catch(() => null);
  if (!client) return { ok: false };
  let request: ValidatedAuthorizationRequest;
  try {
    request = validateAuthorizationRequest(pushed.params, client, deps.config);
  } catch {
    return { ok: false };
  }
  return { ok: true, client, request, requestUri: interaction.requestUri, subject: interaction.subject };
}

export function registerInteraction(app: FastifyInstance, deps: EndpointDeps): void {
  const paths = endpointPaths(deps.config);
  const iss = deps.config.issuer;

  // GET /interaction?id=... — dispatch to login (unauthenticated / re-auth) or
  // consent (authenticated).
  app.get(paths.interaction, async (req, reply) => {
    const id = str((req.query as Record<string, unknown>).id);
    if (!id) return html(reply, 400, renderError("missing interaction id"));
    const ctx = await loadInteractionContext(id, deps, new Date());
    if (!ctx.ok) return html(reply, 400, renderError("this authorization request is invalid or has expired"));

    const session = sessionFrom(req, deps.config);
    const nowSec = Math.floor(Date.now() / 1000);
    if (needsReauthentication(session, ctx.request, nowSec)) {
      return html(reply, 200, renderLogin({
        action: paths.interactionLogin,
        interactionId: id,
        csrfToken: issueCsrfToken(id, deps.config.sessionSecret),
        users: deps.config.devLoginUsers,
      }));
    }
    // Authenticated → bind the interaction to this subject and show consent.
    const s = session as LoginSession;
    await deps.storage.interactions.setSubject(
      id,
      s.sub,
      new Date(s.authTime * 1000),
      s.acr ?? null,
      s.amr ?? null,
    );
    // The approve/deny submission 303-redirects to the client's registered
    // redirect_uri (cross-origin), so form-action must permit that one origin;
    // the global BASE_CSP ('self' only) would otherwise block the redirect.
    reply.header("content-security-policy", consentCsp(ctx.request.redirectUri));
    return html(reply, 200, renderConsent({
      action: paths.interactionConsent,
      interactionId: id,
      // CSRF bound to the login session (per-session secret factor), not just
      // the interaction id — the consent POST carries a session cookie.
      csrfToken: issueCsrfToken(s.sid, deps.config.sessionSecret),
      clientName: ctx.client.clientName ?? ctx.client.clientId,
      scopes: ctx.request.scope.split(" ").filter(Boolean),
      subject: s.sub,
    }));
  });

  // POST /interaction/login — authenticate, establish the login session,
  // return to the interaction (→ consent).
  app.post(paths.interactionLogin, async (req, reply) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const id = str(body.interaction_id);
    if (!id) return html(reply, 400, renderError("missing interaction id"));
    if (!verifyCsrfToken(str(body.csrf), id, deps.config.sessionSecret)) {
      return html(reply, 403, renderError("invalid or missing CSRF token"));
    }
    const ctx = await loadInteractionContext(id, deps, new Date());
    if (!ctx.ok) return html(reply, 400, renderError("this authorization request is invalid or has expired"));

    const user = await deps.authProvider.authenticate({ username: str(body.username) });
    if (!user) {
      return html(reply, 200, renderLogin({
        action: paths.interactionLogin,
        interactionId: id,
        csrfToken: issueCsrfToken(id, deps.config.sessionSecret),
        users: deps.config.devLoginUsers,
        error: "unknown user",
      }));
    }
    const session: LoginSession = {
      sid: newSessionId(),
      sub: user.sub,
      authTime: Math.floor(user.authTime.getTime() / 1000),
      exp: Math.floor(Date.now() / 1000) + deps.config.sessionTtlSec,
      acr: user.acr,
      amr: user.amr,
    };
    return reply
      .header("set-cookie", sessionCookie(sealSession(session, deps.config.sessionSecret), deps.config.sessionTtlSec))
      .header("cache-control", "no-store")
      .redirect(`${paths.interaction}?id=${encodeURIComponent(id)}`, 303);
  });

  // POST /interaction/consent — approve (→ code) or deny (→ access_denied).
  app.post(paths.interactionConsent, async (req, reply) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const id = str(body.interaction_id);
    if (!id) return html(reply, 400, renderError("missing interaction id"));
    const session = sessionFrom(req, deps.config);
    if (!session) return html(reply, 400, renderError("your session has expired; please restart the flow"));
    // CSRF bound to the login session (the token was minted for this session).
    if (!verifyCsrfToken(str(body.csrf), session.sid, deps.config.sessionSecret)) {
      return html(reply, 403, renderError("invalid or missing CSRF token"));
    }

    const ctx = await loadInteractionContext(id, deps, new Date());
    if (!ctx.ok) return html(reply, 400, renderError("this authorization request is invalid or has expired"));
    // Session-integrity (FAPI2 Attacker Model §5.4): the code may only be
    // issued for the subject the consent screen was rendered and approved for.
    // A session swap between GET (render) and POST (submit) is rejected.
    if (ctx.subject === null || ctx.subject !== session.sub) {
      return html(reply, 400, renderError("your session changed; please restart the authorization"));
    }

    const user: AuthenticatedUser = {
      sub: session.sub,
      authTime: new Date(session.authTime * 1000),
      acr: session.acr,
      amr: session.amr,
    };
    const approved = str(body.decision) === "approve";

    // Complete the interaction (one-time) — the authorization action.
    const done = await deps.storage.interactions.complete(id, new Date());
    if (!done) return html(reply, 400, renderError("this authorization request has already been completed"));

    let allowed = false;
    try {
      ({ allowed } = await decideAuthorization(deps.pdp, {
        user,
        client: ctx.client,
        request: ctx.request,
        userApproved: approved,
      }));
    } catch {
      allowed = false;
    }
    if (!allowed) {
      // Invalidate the request_uri too (RFC 9126 §4 one-time use): a declined
      // authorization request must not be replayable.
      await deps.storage.par.consume(ctx.requestUri, new Date());
      return redirectError(reply, ctx.request.redirectUri, "access_denied", "authorization was not granted", ctx.request.state, iss);
    }
    return issueCodeForInteraction(reply, { requestUri: ctx.requestUri, client: ctx.client, request: ctx.request, user }, deps, iss);
  });
}

/**
 * Consume the PAR request_uri (authorization action) and issue the code, then
 * redirect to the client. Shared by consent-approval and the prompt=none path.
 */
export async function issueCodeForInteraction(
  reply: FastifyReply,
  input: {
    requestUri: string;
    client: Client;
    request: ValidatedAuthorizationRequest;
    user: AuthenticatedUser;
  },
  deps: EndpointDeps,
  iss: string,
): Promise<FastifyReply> {
  // RFC 9126 §4 / FAPI2-AUTHZ-15: consume the request_uri now (one-time use).
  const consumed = await deps.storage.par.consume(input.requestUri, new Date());
  if (!consumed) {
    return redirectError(reply, input.request.redirectUri, "invalid_request", "request_uri is no longer valid", input.request.state, iss);
  }
  try {
    const { code } = await issueAuthorizationCode(
      { client: input.client, user: input.user, request: input.request },
      deps,
    );
    return redirectCode(reply, input.request.redirectUri, code, input.request.state, iss);
  } catch (err) {
    void invalidGrant; // reserved for future grant-issuance error mapping
    throw err;
  }
}
