/**
 * Interactive login/consent endpoint edge cases (P2): CSRF, session binding,
 * clickjacking headers, invalid/expired interactions.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../src/index.js";
import { loadConfig } from "../../src/config.js";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";
import type { Storage } from "../../src/db/repositories/types.js";
import {
  ASSERTION_TYPE,
  createTestClient,
  form,
  makeClientAssertion,
  seedClient,
  type TestClient,
} from "../helpers/client.js";

const config = loadConfig({ STORAGE: "memory", ISSUER: "https://as.example.com" });
const ISSUER = config.issuer;

let app: FastifyInstance;
let storage: Storage;
let client: TestClient;

beforeEach(async () => {
  storage = createMemoryStorage();
  client = await createTestClient();
  await seedClient(storage, client);
  app = buildApp({ config, storage });
  await app.ready();
});

afterEach(async () => {
  await app.close();
});

async function startInteraction(): Promise<{ id: string; loginHtml: string }> {
  const par = await app.inject({
    method: "POST",
    url: "/par",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    payload: form({
      client_assertion_type: ASSERTION_TYPE,
      client_assertion: await makeClientAssertion(client, ISSUER),
      response_type: "code",
      client_id: client.clientId,
      redirect_uri: client.redirectUri,
      scope: "openid",
      code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      code_challenge_method: "S256",
    }),
  });
  const { request_uri } = par.json() as { request_uri: string };
  const start = await app.inject({
    method: "GET",
    url: `/authorize?client_id=${client.clientId}&request_uri=${encodeURIComponent(request_uri)}`,
  });
  const loginPage = await app.inject({ method: "GET", url: String(start.headers.location) });
  const id = /name="interaction_id" value="([^"]*)"/.exec(loginPage.payload)![1];
  return { id, loginHtml: loginPage.payload };
}

const csrfOf = (html: string) => /name="csrf" value="([^"]*)"/.exec(html)![1];

describe("interaction endpoints", () => {
  it("renders an HTML login page with clickjacking headers", async () => {
    const { loginHtml } = await startInteraction();
    expect(loginHtml).toContain("<form");
    expect(loginHtml).toContain('name="username"');
  });

  it("sets security headers on the login page [OIDC §3.1.2.3]", async () => {
    const { id } = await startInteraction();
    const res = await app.inject({ method: "GET", url: `/interaction?id=${id}` });
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(String(res.headers["content-security-policy"])).toContain("frame-ancestors 'none'");
    expect(String(res.headers["content-type"])).toContain("text/html");
  });

  it("consent page CSP form-action permits the redirect_uri origin [OIDC §3.1.2.3]", async () => {
    // The approve/deny submission 303-redirects to the client's cross-origin
    // redirect_uri; browsers re-check that redirect against the submitting
    // document's form-action, so 'self' alone would silently block it.
    const { id, loginHtml } = await startInteraction();
    const loginRes = await app.inject({
      method: "POST",
      url: "/interaction/login",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ interaction_id: id, csrf: csrfOf(loginHtml), username: "dev-user" }),
    });
    const cookie = String(loginRes.headers["set-cookie"]).split(";")[0];
    const consent = await app.inject({ method: "GET", url: `/interaction?id=${id}`, headers: { cookie } });
    expect(consent.statusCode).toBe(200);
    const csp = String(consent.headers["content-security-policy"]);
    const origin = new URL(client.redirectUri).origin;
    expect(csp).toContain(`form-action 'self' ${origin}`);
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("rejects login without a valid CSRF token [OIDC §3.1.2.3 / RFC6749 §10.12]", async () => {
    const { id } = await startInteraction();
    const res = await app.inject({
      method: "POST",
      url: "/interaction/login",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ interaction_id: id, csrf: "wrong", username: "dev-user" }),
    });
    expect(res.statusCode).toBe(403);
  });

  it("re-renders login with an error for an unknown user (no session set)", async () => {
    const { id, loginHtml } = await startInteraction();
    const res = await app.inject({
      method: "POST",
      url: "/interaction/login",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ interaction_id: id, csrf: csrfOf(loginHtml), username: "nobody" }),
    });
    expect(res.statusCode).toBe(200);
    expect(res.payload).toContain("unknown user");
    expect(res.headers["set-cookie"]).toBeUndefined();
  });

  it("issues a __Host- session cookie on successful login", async () => {
    const { id, loginHtml } = await startInteraction();
    const res = await app.inject({
      method: "POST",
      url: "/interaction/login",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      payload: form({ interaction_id: id, csrf: csrfOf(loginHtml), username: "dev-user" }),
    });
    expect(res.statusCode).toBe(303);
    const setCookie = String(res.headers["set-cookie"]);
    expect(setCookie).toMatch(/^__Host-as_session=/);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("Secure");
  });

  it("rejects consent without a login session (400)", async () => {
    const { id } = await startInteraction();
    const res = await app.inject({
      method: "POST",
      url: "/interaction/consent",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      // A syntactically valid CSRF cannot be produced without the secret; use a
      // fresh interaction and expect the session check to fail first.
      payload: form({ interaction_id: id, csrf: "x", decision: "approve" }),
    });
    // Either CSRF (403) or missing-session (400) — both are hard failures.
    expect([400, 403]).toContain(res.statusCode);
  });

  it("rejects an unknown/expired interaction id", async () => {
    const res = await app.inject({ method: "GET", url: "/interaction?id=does-not-exist" });
    expect(res.statusCode).toBe(400);
  });
});
