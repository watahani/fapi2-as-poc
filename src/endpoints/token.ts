/**
 * Token endpoint (RFC 6749 §3.2 + §4.1.3/§6; RFC 7523 client auth; RFC 9449
 * DPoP; RFC 9068 JWT AT; OIDC ID Token). FAPI2 5.3.2.1: confidential clients,
 * sender-constrained tokens, no ROPC, no refresh-token rotation.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { endpointPaths, endpointUrls } from "../config.js";
import { authenticateClient } from "../domain/client-auth.js";
import { verifyDpopProof } from "../domain/dpop.js";
import { invalidRequest, unsupportedGrantType, OAuthError } from "../domain/errors.js";
import { loadRefreshGrant, redeemAuthorizationCode } from "../domain/grant.js";
import { issueTokenSet } from "../domain/tokens.js";
import type { Client } from "../domain/clients.js";
import type { EndpointDeps } from "./index.js";

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v !== "" ? v : undefined;

function scopeSubset(requested: string, granted: string): boolean {
  const allowed = new Set(granted.split(" ").filter(Boolean));
  return requested.split(" ").filter(Boolean).every((s) => allowed.has(s));
}

export function registerToken(app: FastifyInstance, deps: EndpointDeps): void {
  const path = endpointPaths(deps.config).token;
  const htu = endpointUrls(deps.config).token;

  app.post(path, async (req: FastifyRequest, reply: FastifyReply) => {
    if (!deps.rateLimiter.allow(req.ip)) {
      return reply
        .headers({ "cache-control": "no-store" })
        .code(429)
        .send({ error: "invalid_request", error_description: "too many requests" });
    }
    if (!req.headers["content-type"]?.toLowerCase().startsWith("application/x-www-form-urlencoded")) {
      throw invalidRequest("content-type must be application/x-www-form-urlencoded [RFC6749 §3.2]");
    }
    const body = (req.body ?? {}) as Record<string, unknown>;

    // FAPI2 5.3.2.1(2) / BCP-2: ROPC is rejected before touching credentials.
    const grantType = str(body.grant_type);
    if (grantType === "password") {
      throw unsupportedGrantType("the resource owner password credentials grant is not supported [FAPI2 5.3.2.1(2)]");
    }

    // RFC 6749 §3.2.1: confidential client authentication (private_key_jwt).
    const client = await authenticateClient(
      { body, authorizationHeader: req.headers.authorization },
      deps,
    );

    // RFC 9449 §5 / FAPI2 5.3.2.1(4): every access token is DPoP-bound, so a
    // valid proof for htm=POST, htu=token endpoint is required.
    if (client.metadata.dpop_bound_access_tokens === false) {
      throw invalidRequest("this authorization server only issues sender-constrained tokens [FAPI2 5.3.2.1(4)]");
    }
    const { jkt } = await verifyDpopProof(req.headers.dpop, {
      htm: "POST",
      htu,
      config: deps.config,
      storage: deps.storage,
    });

    // The signing key must be loaded before minting tokens (lazy init keeps
    // liveness independent of the DB — see KeyStore.ensure).
    await deps.keystore.ensure();

    let response;
    switch (grantType) {
      case "authorization_code":
        response = await handleAuthorizationCode(body, client, jkt, deps);
        break;
      case "refresh_token":
        response = await handleRefreshToken(body, client, jkt, deps);
        break;
      case undefined:
        throw invalidRequest("grant_type is required [RFC6749 §3.2]");
      default:
        throw unsupportedGrantType(`unsupported grant_type: ${grantType}`);
    }

    req.log.info(
      { audit: "token", grantType, clientId: client.clientId },
      "token issued",
    );
    // RFC 6749 §5.1 / OIDC §3.1.3.3: JSON, no-store.
    return reply
      .headers({ "cache-control": "no-store", pragma: "no-cache" })
      .code(200)
      .send(response);
  });
}

async function handleAuthorizationCode(
  body: Record<string, unknown>,
  client: Client,
  jkt: string,
  deps: EndpointDeps,
) {
  const code = str(body.code);
  if (!code) throw invalidRequest("code is required [RFC6749 §4.1.3]");

  const { record, grant } = await redeemAuthorizationCode(
    {
      code,
      clientId: client.clientId,
      redirectUri: str(body.redirect_uri),
      codeVerifier: str(body.code_verifier),
      dpopJkt: jkt,
    },
    deps,
  );

  const openid = grant.scope.split(" ").includes("openid");
  return issueTokenSet(
    {
      grantId: grant.grantId,
      clientId: client.clientId,
      subject: grant.subject,
      scope: grant.scope,
      cnfJkt: jkt,
      authTime: grant.authTime,
      nonce: record.nonce,
      openid,
      // Issue a refresh token only to clients registered for the grant
      // (least privilege — BCP-8; avoids handing every client a long-lived RT).
      withRefreshToken: client.metadata.grant_types.includes("refresh_token"),
    },
    deps,
  );
}

async function handleRefreshToken(
  body: Record<string, unknown>,
  client: Client,
  jkt: string,
  deps: EndpointDeps,
) {
  const refreshToken = str(body.refresh_token);
  if (!refreshToken) throw invalidRequest("refresh_token is required [RFC6749 §6]");

  const { grant, scope: grantedScope } = await loadRefreshGrant(
    { refreshToken, clientId: client.clientId },
    deps,
  );

  // RFC 6749 §6: requested scope must not exceed the originally granted scope.
  // A whitespace-only scope is treated as omitted (RFC 6749 §3.1/§3.3).
  const requestedRaw = str(body.scope);
  const requested = requestedRaw && requestedRaw.trim() !== "" ? requestedRaw : undefined;
  if (requested !== undefined && !scopeSubset(requested, grantedScope)) {
    throw new OAuthError("invalid_scope", "requested scope exceeds the original grant [RFC6749 §6]");
  }
  const scope = requested ?? grantedScope;
  const openid = scope.split(" ").includes("openid");

  const tokens = await issueTokenSet(
    {
      grantId: grant.grantId,
      clientId: client.clientId,
      subject: grant.subject,
      scope,
      cnfJkt: jkt,
      authTime: grant.authTime,
      openid,
      // FAPI2 5.3.2.1(9): no rotation — the client keeps its refresh token.
      withRefreshToken: false,
    },
    deps,
  );
  // Echo the same refresh token so clients that expect it in the response keep
  // working (it is unchanged — no rotation).
  return { ...tokens, refresh_token: refreshToken };
}
