/**
 * DPoP proof verification (RFC 9449), the §4.3 checklist as it applies to the
 * authorization server's token endpoint (ath / access-token binding is the
 * resource server's job, §4.3 step 12, and is out of scope here).
 *
 * Success yields the JWK thumbprint (RFC 7638) the issued access token is
 * bound to via cnf.jkt (§6.1). Failures throw invalid_dpop_proof (§5); when a
 * nonce is required they throw use_dpop_nonce with a fresh DPoP-Nonce (§8).
 */
import { createHmac } from "node:crypto";
import {
  EmbeddedJWK,
  calculateJwkThumbprint,
  decodeProtectedHeader,
  jwtVerify,
  type JWK,
} from "jose";
import type { AppConfig } from "../config.js";
import type { Storage } from "../db/repositories/types.js";
import { acceptedJwsAlgs } from "../crypto/jws.js";
import { invalidDpopProof, useDpopNonce } from "./errors.js";

export interface DpopContext {
  /** HTTP method of the request (RFC 9449 §4.2 htm). */
  htm: string;
  /** Canonical endpoint URL (issuer-derived, not request-derived). */
  htu: string;
  config: AppConfig;
  storage: Storage;
  now?: Date;
  /** Resource-server use (RFC 9449 §7): the proof MUST carry `ath` equal to
   * this base64url SHA-256 hash of the presented access token. */
  ath?: string;
  /** Replay-guard context override (defaults to the token endpoint scope). */
  replayContext?: string;
}

export interface DpopResult {
  /** base64url SHA-256 JWK thumbprint of the proof key (cnf.jkt). */
  jkt: string;
}

/** Normalise for htu comparison (RFC 9449 §4.3 step 9 + RFC 3986 §6.2.2/6.2.3):
 * drop query/fragment, lowercase scheme+host (URL already does), and drop the
 * default port so https://h:443/x and https://h/x compare equal. */
function normalizeHtu(url: string): string {
  try {
    const u = new URL(url);
    const defaultPort =
      (u.protocol === "https:" && u.port === "443") || (u.protocol === "http:" && u.port === "80");
    const host = defaultPort ? u.hostname : u.host;
    return `${u.protocol}//${host}${u.pathname}`;
  } catch {
    return url;
  }
}

export async function verifyDpopProof(
  proofHeader: string | string[] | undefined,
  ctx: DpopContext,
): Promise<DpopResult> {
  const now = ctx.now ?? new Date();

  // §4.3 step 1: exactly one DPoP header.
  if (Array.isArray(proofHeader)) {
    throw invalidDpopProof("multiple DPoP headers [RFC9449 §4.3]");
  }
  const proof = proofHeader;
  if (!proof) {
    throw invalidDpopProof("DPoP proof required [RFC9449 §5]");
  }

  // §4.3 step 2 + steps 4/5/7: well-formed JWT; typ, alg, jwk header checks
  // before touching the signature.
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw invalidDpopProof("malformed DPoP proof [RFC9449 §4.3]");
  }
  if (header.typ !== "dpop+jwt") {
    throw invalidDpopProof("DPoP proof typ must be dpop+jwt [RFC9449 §4.2, §11.5]");
  }
  // Accept only the DPoP signing algs the AS advertises
  // (dpop_signing_alg_values_supported), narrowed to the FAPI2 ceiling.
  const allowedAlgs = acceptedJwsAlgs(ctx.config.metadata.dpopSigningAlgs);
  if (!header.alg || !allowedAlgs.includes(header.alg)) {
    throw invalidDpopProof(`DPoP proof alg not allowed: ${String(header.alg)} [FAPI2 5.4.1]`);
  }
  const jwk = header.jwk as (JWK & { d?: string }) | undefined;
  if (!jwk || typeof jwk !== "object") {
    throw invalidDpopProof("DPoP proof jwk header required [RFC9449 §4.2]");
  }
  if (jwk.d !== undefined) {
    throw invalidDpopProof("DPoP proof jwk must not contain a private key [RFC9449 §4.3]");
  }

  // §4.3 step 6: signature verifies with the embedded public key.
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(proof, EmbeddedJWK, {
      algorithms: allowedAlgs,
      clockTolerance: 10 ** 10, // iat handled below with the profile window
    });
    payload = verified.payload as Record<string, unknown>;
  } catch {
    throw invalidDpopProof("DPoP proof signature invalid [RFC9449 §4.3]");
  }

  // §4.3 step 3: required claims present.
  const { jti, htm, htu, iat, nonce, ath } = payload as {
    jti?: unknown;
    htm?: unknown;
    htu?: unknown;
    iat?: unknown;
    nonce?: unknown;
    ath?: unknown;
  };
  if (typeof jti !== "string" || jti.length === 0) {
    throw invalidDpopProof("DPoP proof jti required [RFC9449 §4.2]");
  }
  // §4.3 step 8: htm matches.
  if (htm !== ctx.htm) {
    throw invalidDpopProof("DPoP proof htm mismatch [RFC9449 §4.3]");
  }
  // §4.3 step 9: htu matches (normalised).
  if (typeof htu !== "string" || normalizeHtu(htu) !== normalizeHtu(ctx.htu)) {
    throw invalidDpopProof("DPoP proof htu mismatch [RFC9449 §4.3]");
  }
  // §4.3 step 11: iat within an acceptance window.
  if (typeof iat !== "number") {
    throw invalidDpopProof("DPoP proof iat required [RFC9449 §4.2]");
  }
  const nowSec = Math.floor(now.getTime() / 1000);
  if (iat > nowSec + ctx.config.clockSkewFutureAcceptSec) {
    throw invalidDpopProof("DPoP proof iat is in the future [RFC9449 §11.1]");
  }
  if (nowSec - iat > ctx.config.dpopProofMaxAgeSec) {
    throw invalidDpopProof("DPoP proof has expired [RFC9449 §11.1]");
  }

  // §4.3 step 12 (RS use): the proof MUST bind the presented access token via
  // `ath` = base64url(SHA-256(access token)).
  if (ctx.ath !== undefined && ath !== ctx.ath) {
    throw invalidDpopProof("DPoP proof ath does not match the access token [RFC9449 §4.3, §7]");
  }

  const jkt = await calculateJwkThumbprint(jwk, "sha256");

  // §8 nonce mechanism (default off, FAPI2 5.3.2.1(10) is MAY). When enabled,
  // §4.3 step 10 / §11.3: a valid recent nonce is required. Nonces are scoped
  // to (key, endpoint, window) so one endpoint's nonce is not valid at another.
  const htuKey = normalizeHtu(ctx.htu);
  if (ctx.config.dpopNonceRequired) {
    if (typeof nonce !== "string" || !validNonce(nonce, jkt, htuKey, ctx.config, now)) {
      throw useDpopNonce(issueNonce(jkt, htuKey, ctx.config, now));
    }
  }

  // §11.1 replay: reject a jti reused within the acceptance window, scoped to
  // the proof key + endpoint. base64url-joined so the pg text key is NUL-free.
  const replayId = `${jkt}.${Buffer.from(jti, "utf8").toString("base64url")}`;
  const fresh = await ctx.storage.jti.register(
    ctx.replayContext ?? `dpop:${normalizeHtu(ctx.htu)}`,
    replayId,
    new Date((iat + ctx.config.dpopProofMaxAgeSec + ctx.config.clockSkewFutureAcceptSec) * 1000),
    now,
  );
  if (!fresh) {
    throw invalidDpopProof("DPoP proof replay detected [RFC9449 §11.1]");
  }

  return { jkt };
}

/**
 * Stateless HMAC nonce bound to the proof key and a coarse time window
 * (RFC 9449 §8: unpredictable, server-verifiable). Two windows are accepted
 * on validation to smooth rotation.
 */
const NONCE_WINDOW_SEC = 60;

function nonceFor(jkt: string, htu: string, window: number, config: AppConfig): string {
  // config.dpopNonceSecret is always a real secret (explicit, or a random
  // per-process value) — never the public issuer.
  return createHmac("sha256", config.dpopNonceSecret)
    .update(`${jkt}:${htu}:${window}`)
    .digest("base64url");
}

export function issueNonce(jkt: string, htu: string, config: AppConfig, now: Date): string {
  return nonceFor(jkt, htu, Math.floor(now.getTime() / 1000 / NONCE_WINDOW_SEC), config);
}

function validNonce(nonce: string, jkt: string, htu: string, config: AppConfig, now: Date): boolean {
  const w = Math.floor(now.getTime() / 1000 / NONCE_WINDOW_SEC);
  return nonce === nonceFor(jkt, htu, w, config) || nonce === nonceFor(jkt, htu, w - 1, config);
}
