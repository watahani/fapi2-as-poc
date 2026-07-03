/**
 * Authorization-response redirect helpers, shared by the authorization
 * endpoint and the interaction (consent) endpoint.
 */
import type { FastifyReply } from "fastify";
import { sanitizeErrorDescription, type AuthorizeErrorCode } from "../domain/errors.js";

/** Baseline response CSP (clickjacking + injection defence). `form-action
 * 'self'` is deliberately strict for every response EXCEPT the consent page,
 * whose form submission legitimately 303-redirects to the client's registered
 * redirect_uri (a cross-origin navigation). Browsers re-check the redirect
 * target of a form submission against the submitting document's form-action,
 * so the consent page must widen form-action to that one already-validated
 * origin (see consentCsp) — otherwise the authorization redirect is blocked. */
export const BASE_CSP =
  "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/** CSP for the consent page: BASE_CSP plus the origin of the redirect_uri the
 * approve/deny submission will navigate to. The origin is taken from the
 * redirect_uri that authorization-request validation already registered and
 * exact-matched, so this widens form-action by exactly one trusted origin. */
export function consentCsp(redirectUri: string): string {
  return `${BASE_CSP} ${new URL(redirectUri).origin}`;
}

/** Add response parameters to the redirect URI's query component. Any
 * pre-registered param of the same name is REPLACED, not appended, so a
 * registered `?iss=`/`?state=` cannot inject a second value that a client
 * reading the first occurrence would trust (RFC 9207 mix-up / OAUTH-4). */
export function buildRedirect(redirectUri: string, params: Record<string, string>): string {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  return url.toString();
}

/** RFC 6749 §4.1.2.1: deliver an error directly (no redirect) when the
 * redirect target is not trusted. */
export function errorPage(
  reply: FastifyReply,
  error: AuthorizeErrorCode,
  description: string,
): FastifyReply {
  return reply
    .header("cache-control", "no-store")
    .code(400)
    .send({ error, error_description: sanitizeErrorDescription(description) });
}

/** Authorization error delivered by 303 redirect to a trusted redirect_uri
 * (RFC 6749 §4.1.2.1 / RFC 9207 iss). */
export function redirectError(
  reply: FastifyReply,
  redirectUri: string,
  error: AuthorizeErrorCode,
  description: string | undefined,
  state: string | undefined,
  iss: string,
): FastifyReply {
  const location = buildRedirect(redirectUri, {
    error,
    ...(description ? { error_description: sanitizeErrorDescription(description) } : {}),
    ...(state !== undefined ? { state } : {}),
    iss,
  });
  return reply.header("cache-control", "no-store").redirect(location, 303);
}

/** Successful authorization-code response (RFC 6749 §4.1.2 + RFC 9207 §2). */
export function redirectCode(
  reply: FastifyReply,
  redirectUri: string,
  code: string,
  state: string | undefined,
  iss: string,
): FastifyReply {
  const location = buildRedirect(redirectUri, {
    code,
    ...(state !== undefined ? { state } : {}),
    iss,
  });
  // FAPI2 5.3.2.2(11): 303 (never 307 for credentialed redirects).
  return reply.header("cache-control", "no-store").redirect(location, 303);
}
