/**
 * Stateless signed-cookie login session + CSRF tokens for the interaction
 * endpoints (login / consent). FAPI2 Attacker Model §5.4 (session integrity),
 * OIDC Core §3.1.2.3 (CSRF), RFC 6749 §10.12.
 *
 * The login session is a compact `payload.hmac` value (both base64url); the
 * HMAC (SHA-256 over the payload with SESSION_SECRET) makes it tamper-evident,
 * so it can live in a `__Host-` cookie without server-side storage. CSRF
 * tokens are HMAC'd over the session id so a form submission must originate
 * from the same session.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export interface LoginSession {
  /** Opaque session id (anti-CSRF anchor; rotates on each login). */
  sid: string;
  sub: string;
  authTime: number; // seconds since epoch
  /** Expiry (seconds since epoch); enforced by openSession — a stolen cookie
   * is not valid forever even though the session is stateless. */
  exp: number;
  acr?: string;
  amr?: string[];
}

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf as never).toString("base64url");
}

function hmac(secret: string, data: string): Buffer {
  return createHmac("sha256", secret).update(data).digest();
}

/** Constant-time string compare (both base64url/ascii). */
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Encode a login session as `payload.sig` (both base64url). */
export function sealSession(session: LoginSession, secret: string): string {
  const payload = b64url(JSON.stringify(session));
  const sig = b64url(hmac(secret, payload));
  return `${payload}.${sig}`;
}

/** Verify + decode a sealed session; null if absent/tampered/malformed or
 * expired (checked against `nowSec`). */
export function openSession(
  value: string | undefined,
  secret: string,
  nowSec: number = Math.floor(Date.now() / 1000),
): LoginSession | null {
  if (!value) return null;
  const dot = value.indexOf(".");
  if (dot <= 0) return null;
  const payload = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  if (!safeEqual(sig, b64url(hmac(secret, payload)))) return null;
  try {
    const obj = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as LoginSession;
    if (
      typeof obj.sid !== "string" ||
      typeof obj.sub !== "string" ||
      typeof obj.authTime !== "number" ||
      typeof obj.exp !== "number"
    ) {
      return null;
    }
    if (obj.exp <= nowSec) return null; // expired
    return obj;
  } catch {
    return null;
  }
}

export function newSessionId(): string {
  return randomBytes(16).toString("base64url");
}

/** CSRF token bound to a session id (HMAC), so a form POST must carry a token
 * minted for the current session. */
export function issueCsrfToken(sid: string, secret: string): string {
  return b64url(hmac(secret, `csrf:${sid}`));
}

export function verifyCsrfToken(token: string | undefined, sid: string, secret: string): boolean {
  if (!token) return false;
  return safeEqual(token, issueCsrfToken(sid, secret));
}

/** `__Host-` cookie name for the login session (requires Secure + path=/ +
 * no Domain, which the browser enforces — a strong same-origin binding). */
export const SESSION_COOKIE = "__Host-as_session";

/** Serialize a Set-Cookie for the login session. maxAgeSec<=0 clears it. */
export function sessionCookie(value: string, maxAgeSec: number): string {
  const attrs = ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"];
  const ma = maxAgeSec <= 0 ? "Max-Age=0" : `Max-Age=${maxAgeSec}`;
  return `${SESSION_COOKIE}=${maxAgeSec <= 0 ? "" : value}; ${attrs.join("; ")}; ${ma}`;
}

/** Parse a specific cookie value from a Cookie header. */
export function readCookie(cookieHeader: string | undefined, name: string): string | undefined {
  if (!cookieHeader) return undefined;
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}
