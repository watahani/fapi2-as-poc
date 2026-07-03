/**
 * Authorization request validation, shared by the PAR endpoint (which must
 * validate the pushed request "as it would an authorization request sent to
 * the authorization endpoint", RFC 9126 §2.1) and the authorization endpoint
 * itself (RFC 9126 §4 re-validation).
 *
 * Errors here are thrown as OAuthError: at the PAR endpoint they surface as
 * RFC 6749 §5.2 JSON; the authorization endpoint maps them onto redirect
 * error responses once the redirect_uri is known-good (OIDC-10).
 */
import type { AppConfig } from "../config.js";
import { invalidRequest, invalidScope, OAuthError } from "./errors.js";
import { redirectUriRegistered, scopeAllowed, type Client } from "./clients.js";

/** RFC 6749 Appendix A: state/nonce etc. are VSCHAR (%x20-7E) strings. */
const VSCHAR = /^[\x20-\x7e]*$/;
/** RFC 7636 §4.2: base64url output of SHA-256 — 43 chars of unreserved. */
const CODE_CHALLENGE = /^[A-Za-z0-9\-._~]{43,128}$/;
/** RFC 7638 SHA-256 thumbprint: 43 base64url chars (RFC 9449 §10). */
const JKT = /^[A-Za-z0-9_-]{43}$/;

export interface ValidatedAuthorizationRequest {
  clientId: string;
  responseType: "code";
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  state?: string;
  nonce?: string;
  dpopJkt?: string;
  prompt?: string;
  /** Parsed max_age (seconds) — forces re-authentication when exceeded. */
  maxAge?: number;
  /** Recognised OIDC authentication params carried through PAR to /authorize
   * (acr_values/max_age/... — dropping them would silently ignore requested
   * authentication context, RFC 9126 §2.2). */
  passthrough: Record<string, string>;
}

/** OIDC authentication-request params the AS understands and must preserve
 * from PAR to the authorization endpoint. */
const PASSTHROUGH_PARAMS = [
  "acr_values",
  "max_age",
  "login_hint",
  "id_token_hint",
  "ui_locales",
  "claims",
  "claims_locales",
  "display",
] as const;

/** Normalise a form value: absent, empty ("param=" or bare "param" — treated
 * as omitted per RFC 6749 §3.1), or a single string. Arrays (repeated
 * parameters) are rejected by the caller-facing check below. */
function param(body: Record<string, unknown>, name: string): string | undefined {
  const v = body[name];
  if (v === undefined || v === "") return undefined;
  if (Array.isArray(v)) {
    throw invalidRequest(`parameter ${name} must not be repeated [RFC6749 §3.1]`);
  }
  return typeof v === "string" ? v : undefined;
}

export function validateAuthorizationRequest(
  body: Record<string, unknown>,
  client: Client,
  _config: AppConfig,
): ValidatedAuthorizationRequest {
  // Signed request objects (RFC 9101) are out of scope for this profile —
  // plain PAR satisfies FAPI2 (docs/REQUIREMENTS-P1.md scope note).
  if (param(body, "request") !== undefined) {
    throw invalidRequest("request objects are not supported [RFC9126 §3]");
  }

  // The pushed client_id must be the authenticated client (RFC 9126 §2.2
  // binding; RFC 9126 §3 mismatch rule).
  const clientId = param(body, "client_id");
  if (clientId !== undefined && clientId !== client.clientId) {
    throw invalidRequest("client_id does not match the authenticated client [RFC9126 §2.1]");
  }

  // FAPI2 5.3.2.2(1): response_type=code only.
  const responseType = param(body, "response_type");
  if (responseType === undefined) {
    throw invalidRequest("response_type is required [RFC6749 §4.1.1]");
  }
  if (responseType !== "code") {
    throw new OAuthError("unsupported_response_type", "only response_type=code is supported [FAPI2 5.3.2.2(1)]");
  }

  // FAPI2 5.3.2.2(6): redirect_uri required in the pushed request; exact
  // string match against registration (RFC 9700 §2.1 / BCP-1).
  const redirectUri = param(body, "redirect_uri");
  if (redirectUri === undefined) {
    throw invalidRequest("redirect_uri is required [FAPI2 5.3.2.2(6)]");
  }
  if (!redirectUriRegistered(client, redirectUri)) {
    throw invalidRequest("redirect_uri is not registered for this client [RFC9700 §2.1]");
  }

  // Scope: omitted OR whitespace-only → the client's registered default
  // (RFC 6749 §3.3); requested scopes must be within registration.
  const rawScope = param(body, "scope");
  const scope =
    rawScope && rawScope.trim() !== "" ? rawScope : client.metadata.scope;
  if (!VSCHAR.test(scope) || scope.length > 512) {
    throw invalidRequest("malformed scope");
  }
  if (!scopeAllowed(client, scope)) {
    throw invalidScope("requested scope exceeds the client registration [RFC6749 §3.3]");
  }

  // PKCE S256, mandatory (FAPI2 5.3.2.2(5); RFC 7636 §4.4.1 error wording).
  const codeChallenge = param(body, "code_challenge");
  if (codeChallenge === undefined) {
    throw invalidRequest("code challenge required [RFC7636 §4.4.1]");
  }
  const method = param(body, "code_challenge_method");
  // RFC 7636 §4.3: absent method defaults to "plain", which FAPI2 forbids.
  if (method !== "S256") {
    throw invalidRequest("transform algorithm not supported (S256 required) [RFC7636 §4.4.1; FAPI2 5.3.2.2(5)]");
  }
  if (!CODE_CHALLENGE.test(codeChallenge)) {
    throw invalidRequest("malformed code_challenge [RFC7636 §4.2]");
  }

  // OAUTH-13: sanitise state; FAPI2-AUTHZ-14: nonce up to 64 chars must be
  // supported (longer values are accepted here up to a sanity bound).
  const state = param(body, "state");
  if (state !== undefined && (!VSCHAR.test(state) || state.length > 512)) {
    throw invalidRequest("malformed state [RFC6749 §10.14]");
  }
  const nonce = param(body, "nonce");
  if (nonce !== undefined && (!VSCHAR.test(nonce) || nonce.length > 512)) {
    throw invalidRequest("malformed nonce");
  }

  // RFC 9449 §10.1: dpop_jkt pushed via PAR.
  const dpopJkt = param(body, "dpop_jkt");
  if (dpopJkt !== undefined && !JKT.test(dpopJkt)) {
    throw invalidRequest("malformed dpop_jkt (expected a base64url SHA-256 JWK thumbprint) [RFC9449 §10]");
  }

  // OIDC §15.1 minimum support: prompt/display/ui_locales/... must not cause
  // an error; prompt is retained for interaction handling (P1-c), the rest
  // are accepted and ignored (RFC 6749 §3.1 unknown-parameter rule).
  const prompt = param(body, "prompt");
  if (prompt !== undefined) {
    const values = prompt.split(" ").filter(Boolean);
    if (values.includes("none") && values.length > 1) {
      throw invalidRequest("prompt=none must not be combined with other values [OIDC §3.1.2.1]");
    }
  }

  // Preserve recognised OIDC auth params so /authorize (P1-c) can honour them.
  const passthrough: Record<string, string> = {};
  for (const name of PASSTHROUGH_PARAMS) {
    const value = param(body, name);
    if (value !== undefined) {
      if (!VSCHAR.test(value) || value.length > 2048) {
        throw invalidRequest(`malformed ${name}`);
      }
      passthrough[name] = value;
    }
  }

  // max_age (OIDC §3.1.2.1): non-negative integer seconds; forces re-auth.
  let maxAge: number | undefined;
  const maxAgeRaw = param(body, "max_age");
  if (maxAgeRaw !== undefined) {
    if (!/^\d+$/.test(maxAgeRaw)) throw invalidRequest("malformed max_age [OIDC §3.1.2.1]");
    maxAge = Number(maxAgeRaw);
  }

  return {
    clientId: client.clientId,
    responseType: "code",
    redirectUri,
    scope,
    codeChallenge,
    codeChallengeMethod: "S256",
    state,
    nonce,
    dpopJkt,
    prompt,
    maxAge,
    passthrough,
  };
}

/** Flatten for storage in the PAR record (string map, no undefined). */
export function toStoredParams(v: ValidatedAuthorizationRequest): Record<string, string> {
  const out: Record<string, string> = {
    client_id: v.clientId,
    response_type: v.responseType,
    redirect_uri: v.redirectUri,
    scope: v.scope,
    code_challenge: v.codeChallenge,
    code_challenge_method: v.codeChallengeMethod,
  };
  if (v.state !== undefined) out.state = v.state;
  if (v.nonce !== undefined) out.nonce = v.nonce;
  if (v.dpopJkt !== undefined) out.dpop_jkt = v.dpopJkt;
  if (v.prompt !== undefined) out.prompt = v.prompt;
  Object.assign(out, v.passthrough);
  return out;
}
