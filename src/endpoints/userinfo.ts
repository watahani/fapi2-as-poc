/**
 * Minimal protected resource — OIDC UserInfo (OIDC Core §5.3) — acting as the
 * resource server for DPoP-bound access tokens (RFC 9449 §7). It exists so the
 * issued sender-constrained tokens can be exercised end to end (and so the
 * conformance suite has a resource endpoint to call).
 *
 * RS-side checks: token presented via the `DPoP` auth scheme (§7.1), the JWT
 * access token verifies + is unexpired + unrevoked, and a valid DPoP proof
 * carries `ath` = hash of the token and a key whose thumbprint equals the
 * token's cnf.jkt.
 */
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { endpointPaths, endpointUrls } from "../config.js";
import { sha256Base64Url } from "../crypto/hash.js";
import { verifyDpopProof } from "../domain/dpop.js";
import { findAccessToken } from "../domain/token-lookup.js";
import type { EndpointDeps } from "./index.js";

/** RFC 6750 §3 / RFC 9449 §7.1 style challenge (no token details leaked). */
function challenge(reply: FastifyReply, status: number, error?: string, desc?: string): FastifyReply {
  const parts = ['DPoP algs="ES256 PS256 EdDSA"'];
  if (error) parts.push(`error="${error}"`);
  if (desc) parts.push(`error_description="${desc}"`);
  return reply
    .header("www-authenticate", parts.join(", "))
    .header("cache-control", "no-store")
    .code(status)
    .send(error ? { error } : undefined);
}

export function registerUserinfo(app: FastifyInstance, deps: EndpointDeps): void {
  const path = endpointPaths(deps.config).userinfo;
  const htu = endpointUrls(deps.config).userinfo;

  const handler = async (req: FastifyRequest, reply: FastifyReply) => {
    const authz = req.headers.authorization;
    // §7.2: a DPoP-bound token MUST be presented via the DPoP scheme, not
    // Bearer. The auth-scheme is case-insensitive (RFC 9110 §11.1).
    const match = authz?.match(/^DPoP +(.+)$/i);
    if (!match) {
      return challenge(reply, 401);
    }
    const token = (match[1] ?? "").trim();
    if (!token) return challenge(reply, 401, "invalid_token", "missing access token");

    const resolved = await findAccessToken(token, deps);
    if (!resolved || resolved.kind !== "access_token") {
      return challenge(reply, 401, "invalid_token", "access token is invalid");
    }
    const at = resolved.record;
    if (at.revokedAt !== null || at.expiresAt.getTime() <= Date.now()) {
      return challenge(reply, 401, "invalid_token", "access token is expired or revoked");
    }
    if (!at.cnfJkt) {
      // This RS only serves sender-constrained tokens.
      return challenge(reply, 401, "invalid_token", "access token is not sender-constrained");
    }

    // §7.1: validate the DPoP proof and bind it to this token + key.
    let jkt: string;
    try {
      ({ jkt } = await verifyDpopProof(req.headers.dpop, {
        htm: req.method,
        htu,
        config: deps.config,
        storage: deps.storage,
        ath: sha256Base64Url(token),
        replayContext: "dpop-rs:userinfo",
      }));
    } catch {
      return challenge(reply, 401, "invalid_dpop_proof", "DPoP proof is invalid");
    }
    // §7.1: the proof key must be the one the token is bound to.
    if (jkt !== at.cnfJkt) {
      return challenge(reply, 401, "invalid_token", "DPoP key does not match the access token binding");
    }

    return reply.header("cache-control", "no-store").send({ sub: at.subject });
  };

  app.get(path, handler);
  app.post(path, handler);
}
