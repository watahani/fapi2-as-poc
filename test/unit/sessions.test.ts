import { describe, expect, it } from "vitest";
import {
  issueCsrfToken,
  newSessionId,
  openSession,
  readCookie,
  sealSession,
  sessionCookie,
  verifyCsrfToken,
  type LoginSession,
} from "../../src/domain/sessions.js";

const SECRET = "test-session-secret-at-least-32-chars";
const NOW = 1_700_000_000;
const session: LoginSession = {
  sid: "s-1",
  sub: "alice",
  authTime: NOW,
  exp: NOW + 3600,
  acr: "urn:dev:pwd",
  amr: ["pwd"],
};

describe("login session (signed cookie)", () => {
  it("round-trips a sealed session", () => {
    const sealed = sealSession(session, SECRET);
    expect(openSession(sealed, SECRET, NOW)).toEqual(session);
  });

  it("rejects an expired session", () => {
    const sealed = sealSession(session, SECRET);
    expect(openSession(sealed, SECRET, NOW + 3601)).toBeNull();
  });

  it("rejects a tampered payload", () => {
    const sealed = sealSession(session, SECRET);
    const [payload, sig] = sealed.split(".");
    const forged = Buffer.from(JSON.stringify({ ...session, sub: "attacker" })).toString("base64url");
    expect(openSession(`${forged}.${sig}`, SECRET)).toBeNull();
    expect(openSession(`${payload}.deadbeef`, SECRET)).toBeNull();
  });

  it("rejects a session signed with a different secret", () => {
    const sealed = sealSession(session, SECRET);
    expect(openSession(sealed, "other-secret")).toBeNull();
  });

  it("returns null for absent/malformed values", () => {
    expect(openSession(undefined, SECRET)).toBeNull();
    expect(openSession("no-dot", SECRET)).toBeNull();
    expect(openSession(".sig", SECRET)).toBeNull();
  });
});

describe("CSRF tokens", () => {
  it("verifies a token minted for the same session id", () => {
    const sid = newSessionId();
    const token = issueCsrfToken(sid, SECRET);
    expect(verifyCsrfToken(token, sid, SECRET)).toBe(true);
  });

  it("rejects a token for a different session or secret, or a missing token", () => {
    const token = issueCsrfToken("s-1", SECRET);
    expect(verifyCsrfToken(token, "s-2", SECRET)).toBe(false);
    expect(verifyCsrfToken(token, "s-1", "other")).toBe(false);
    expect(verifyCsrfToken(undefined, "s-1", SECRET)).toBe(false);
  });
});

describe("cookie helpers", () => {
  it("uses a __Host- cookie with Secure/HttpOnly and clears with Max-Age=0", () => {
    const set = sessionCookie("abc", 3600);
    expect(set).toMatch(/^__Host-as_session=abc;/);
    expect(set).toContain("Secure");
    expect(set).toContain("HttpOnly");
    expect(set).toContain("Max-Age=3600");
    expect(sessionCookie("abc", 0)).toContain("Max-Age=0");
  });

  it("reads a named cookie from a Cookie header", () => {
    expect(readCookie("a=1; __Host-as_session=xyz; b=2", "__Host-as_session")).toBe("xyz");
    expect(readCookie(undefined, "x")).toBeUndefined();
    expect(readCookie("a=1", "x")).toBeUndefined();
  });
});
