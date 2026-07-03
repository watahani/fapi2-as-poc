/**
 * AuthZEN HTTP PDP adapter (docs/REQUIREMENTS-P1.md separation 3). Uses a stub
 * fetch to exercise the request shape and the fail-closed behaviour.
 */
import { describe, expect, it, vi } from "vitest";
import { AuthZenHttpPdp } from "../../src/authz/adapters/authzen-http.js";
import type { EvaluationRequest } from "../../src/authz/pdp.js";

const REQ: EvaluationRequest = {
  subject: { type: "user", id: "alice" },
  action: { name: "oauth.authorize" },
  resource: { type: "oauth_client", id: "client-1" },
  context: { scope: "openid", user_approved: true },
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

describe("AuthZenHttpPdp", () => {
  it("POSTs an AuthZEN evaluation request with bearer auth and returns the decision", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ decision: true, context: { policy: "p1" } }));
    const pdp = new AuthZenHttpPdp({ url: "https://pdp/access/v1/evaluation", token: "t0k", fetchImpl });
    const res = await pdp.evaluate(REQ);
    expect(res.decision).toBe(true);

    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://pdp/access/v1/evaluation");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).authorization).toBe("Bearer t0k");
    const sent = JSON.parse(String(init.body));
    expect(sent.subject).toEqual(REQ.subject);
    expect(sent.action).toEqual(REQ.action);
    expect(sent.resource).toEqual(REQ.resource);
    expect(sent.context.scope).toBe("openid");
  });

  it("denies (fail-closed) on a non-2xx response", async () => {
    const pdp = new AuthZenHttpPdp({ url: "https://pdp/e", fetchImpl: async () => jsonResponse({ decision: true }, 500) });
    expect((await pdp.evaluate(REQ)).decision).toBe(false);
  });

  it("denies when decision is missing or not exactly true", async () => {
    const truthy = new AuthZenHttpPdp({ url: "https://pdp/e", fetchImpl: async () => jsonResponse({ decision: "true" }) });
    expect((await truthy.evaluate(REQ)).decision).toBe(false);
    const missing = new AuthZenHttpPdp({ url: "https://pdp/e", fetchImpl: async () => jsonResponse({}) });
    expect((await missing.evaluate(REQ)).decision).toBe(false);
  });

  it("denies on a transport error", async () => {
    const pdp = new AuthZenHttpPdp({
      url: "https://pdp/e",
      fetchImpl: async () => {
        throw new Error("ECONNREFUSED");
      },
    });
    expect((await pdp.evaluate(REQ)).decision).toBe(false);
  });

  it("denies on malformed (non-JSON) body", async () => {
    const pdp = new AuthZenHttpPdp({
      url: "https://pdp/e",
      fetchImpl: async () => new Response("not json", { status: 200 }),
    });
    expect((await pdp.evaluate(REQ)).decision).toBe(false);
  });

  it("omits the Authorization header when no token is configured", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ decision: true }));
    await new AuthZenHttpPdp({ url: "https://pdp/e", fetchImpl }).evaluate(REQ);
    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).authorization).toBeUndefined();
  });
});
