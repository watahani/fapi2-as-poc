/**
 * Pushed Authorization Requests (RFC 9126).
 *
 * Processing order per §2.1: the endpoint authenticates the client FIRST
 * (see endpoints/par.ts), then (1) rejects a pushed request_uri, then (2)
 * validates the request exactly as the authorization endpoint would.
 */
import { randomBytes } from "node:crypto";
import type { AppConfig } from "../config.js";
import type { Storage } from "../db/repositories/types.js";
import type { Client } from "./clients.js";
import { invalidDpopProof, invalidRequest } from "./errors.js";
import { toStoredParams, validateAuthorizationRequest } from "./authz-request.js";

/** RFC 9126 §2.2/§9: urn:ietf:params:oauth:request_uri:<reference>. */
const REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:";

export interface ParResult {
  request_uri: string;
  expires_in: number;
}

export async function pushAuthorizationRequest(
  body: Record<string, unknown>,
  client: Client,
  deps: {
    storage: Storage;
    config: AppConfig;
    now?: Date;
    /** JWK thumbprint from a DPoP header on the PAR request (RFC 9449 §10.1). */
    dpopHeaderJkt?: string;
  },
): Promise<ParResult> {
  const now = deps.now ?? new Date();

  // RFC 9126 §2.1 step 2: request_uri must not be pushed (an empty value is
  // "sent without a value" and treated as omitted, RFC 6749 §3.1).
  if (body.request_uri !== undefined && body.request_uri !== "") {
    throw invalidRequest("request_uri must not be provided to the PAR endpoint [RFC9126 §2.1]");
  }

  // §2.1 step 3: full authorization request validation.
  const validated = validateAuthorizationRequest(body, client, deps.config);

  // RFC 9449 §10.1: a DPoP proof on the PAR request binds the authorization
  // code to that key exactly like dpop_jkt. If both are present they MUST
  // match; otherwise either one establishes the binding.
  let dpopJkt = validated.dpopJkt ?? null;
  if (deps.dpopHeaderJkt) {
    if (dpopJkt && dpopJkt !== deps.dpopHeaderJkt) {
      throw invalidDpopProof("dpop_jkt does not match the DPoP proof key [RFC9449 §10.1]");
    }
    dpopJkt = deps.dpopHeaderJkt;
  }

  // §2.2: cryptographically strong random reference (256 bits), bound to the
  // client, expiring well under 600s (FAPI2 5.3.2.2(12)).
  const requestUri = REQUEST_URI_PREFIX + randomBytes(32).toString("base64url");
  const expiresIn = deps.config.parTtlSec;
  await deps.storage.par.insert({
    requestUri,
    clientId: client.clientId,
    params: { ...toStoredParams(validated), ...(dpopJkt ? { dpop_jkt: dpopJkt } : {}) },
    dpopJkt,
    expiresAt: new Date(now.getTime() + expiresIn * 1000),
  });

  return { request_uri: requestUri, expires_in: expiresIn };
}

export function isRequestUri(value: string): boolean {
  return value.startsWith(REQUEST_URI_PREFIX);
}
