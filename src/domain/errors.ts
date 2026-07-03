/**
 * OAuth 2.0 error model.
 *
 * Token-endpoint-style errors follow RFC 6749 §5.2 (JSON body, HTTP 400 unless
 * specified otherwise; invalid_client MAY use 401). The PAR endpoint reuses
 * this format (RFC 9126 §2.3). Authorization-endpoint errors (RFC 6749
 * §4.1.2.1 / OIDC Core §3.1.2.6) are represented separately because they are
 * delivered by redirect — except when the client_id/redirect_uri cannot be
 * trusted, in which case redirecting is forbidden (REQUIREMENTS-P1 OIDC-10).
 */

/** RFC 6749 §5.2 + RFC 9449 §12.2 + RFC 7009 §2.2.1 error codes. */
export type TokenErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "invalid_scope"
  | "invalid_dpop_proof"
  | "use_dpop_nonce"
  | "unsupported_token_type"
  | "server_error";

/** RFC 6749 §4.1.2.1 + OIDC Core §3.1.2.6 authorization endpoint error codes. */
export type AuthorizeErrorCode =
  | "invalid_request"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable"
  | "interaction_required"
  | "login_required"
  | "consent_required"
  | "invalid_request_uri"
  | "request_not_supported"
  | "request_uri_not_supported";

export class OAuthError extends Error {
  readonly error: TokenErrorCode;
  readonly description?: string;
  readonly status: number;
  readonly headers: Record<string, string>;

  constructor(
    error: TokenErrorCode,
    description?: string,
    opts: { status?: number; headers?: Record<string, string> } = {},
  ) {
    super(description ? `${error}: ${description}` : error);
    this.name = "OAuthError";
    this.error = error;
    this.description = description;
    this.status = opts.status ?? 400;
    this.headers = opts.headers ?? {};
  }

  /** RFC 6749 §5.2 JSON body. */
  toBody(): { error: string; error_description?: string } {
    return this.description
      ? { error: this.error, error_description: this.description }
      : { error: this.error };
  }
}

export const invalidRequest = (d?: string): OAuthError => new OAuthError("invalid_request", d);

/**
 * RFC 6749 §5.2: invalid_client MAY use 401; when the client used the
 * Authorization header the server MUST respond 401 with WWW-Authenticate.
 * private_key_jwt travels in the body, so 401 without the header is the
 * general shape here (RFC 7523 §3.2 mandates the invalid_client code).
 */
export const invalidClient = (d?: string, opts: { wwwAuthenticate?: string } = {}): OAuthError =>
  new OAuthError("invalid_client", d, {
    status: 401,
    headers: opts.wwwAuthenticate ? { "www-authenticate": opts.wwwAuthenticate } : {},
  });

export const invalidGrant = (d?: string): OAuthError => new OAuthError("invalid_grant", d);
export const unsupportedGrantType = (d?: string): OAuthError =>
  new OAuthError("unsupported_grant_type", d);
export const unauthorizedClient = (d?: string): OAuthError =>
  new OAuthError("unauthorized_client", d);
export const invalidScope = (d?: string): OAuthError => new OAuthError("invalid_scope", d);

/** RFC 9449 §5: invalid DPoP proof at the token endpoint → HTTP 400. */
export const invalidDpopProof = (d?: string): OAuthError => new OAuthError("invalid_dpop_proof", d);

/** RFC 9449 §8: fresh nonce required; DPoP-Nonce response header carries it. */
export const useDpopNonce = (nonce: string, d?: string): OAuthError =>
  new OAuthError("use_dpop_nonce", d ?? "authorization server requires nonce in DPoP proof", {
    headers: { "dpop-nonce": nonce },
  });

/** RFC 7009 §2.2.1. */
export const unsupportedTokenType = (d?: string): OAuthError =>
  new OAuthError("unsupported_token_type", d);

/**
 * Authorization-endpoint error to be delivered by redirect (RFC 6749
 * §4.1.2.1). Thrown only after client_id + redirect_uri have been validated.
 */
export class AuthorizeError extends Error {
  readonly error: AuthorizeErrorCode;
  readonly description?: string;

  constructor(error: AuthorizeErrorCode, description?: string) {
    super(description ? `${error}: ${description}` : error);
    this.name = "AuthorizeError";
    this.error = error;
    this.description = description;
  }
}
