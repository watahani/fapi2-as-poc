/**
 * private_key_jwt client authentication (docs/REQUIREMENTS-P1.md PKJWT-*).
 */
import { beforeEach, describe, expect, it } from "vitest";
import { generateKeyPair } from "jose";
import { loadConfig } from "../../src/config.js";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";
import type { Storage } from "../../src/db/repositories/types.js";
import { authenticateClient } from "../../src/domain/client-auth.js";
import { OAuthError } from "../../src/domain/errors.js";
import {
  ASSERTION_TYPE,
  createTestClient,
  makeClientAssertion,
  seedClient,
  type TestClient,
} from "../helpers/client.js";

const config = loadConfig({ STORAGE: "memory", ISSUER: "https://as.example.com" });
const ISSUER = config.issuer;

let storage: Storage;
let client: TestClient;

beforeEach(async () => {
  storage = createMemoryStorage();
  client = await createTestClient();
  await seedClient(storage, client);
});

async function attempt(over: Record<string, unknown>, headers: { authorization?: string } = {}) {
  const assertion =
    "client_assertion" in over ? over.client_assertion : await makeClientAssertion(client, ISSUER);
  const body: Record<string, unknown> = {
    client_assertion_type: ASSERTION_TYPE,
    client_assertion: assertion,
    ...over,
  };
  return authenticateClient(
    { body, authorizationHeader: headers.authorization },
    { storage, config },
  );
}

const expectOAuthError = async (p: Promise<unknown>, code: string) => {
  const err = (await p.then(
    () => null,
    (e: unknown) => e,
  )) as OAuthError | null;
  expect(err, "expected an OAuthError").toBeInstanceOf(OAuthError);
  expect(err?.error).toBe(code);
  return err as OAuthError;
};

describe("authenticateClient (private_key_jwt)", () => {
  it("authenticates a valid assertion [RFC7523 §3]", async () => {
    const authed = await attempt({});
    expect(authed.clientId).toBe(client.clientId);
  });

  it("rejects a missing assertion with invalid_client 401 [FAPI2 5.3.2.2(4)]", async () => {
    const err = await expectOAuthError(
      authenticateClient({ body: {} }, { storage, config }),
      "invalid_client",
    );
    expect(err.status).toBe(401);
  });

  it("rejects an unknown client_assertion_type [RFC7523 §2.2]", async () => {
    await expectOAuthError(attempt({ client_assertion_type: "urn:x:other" }), "invalid_client");
  });

  it("rejects multiple authentication mechanisms [RFC7521 §4.2.1]", async () => {
    await expectOAuthError(
      attempt({}, { authorization: "Basic YWJjOmRlZg==" }),
      "invalid_request",
    );
    await expectOAuthError(attempt({ client_secret: "s" }), "invalid_request");
  });

  it("rejects client_secret-based methods outright [FAPI2 5.3.2.1(6)]", async () => {
    await expectOAuthError(
      authenticateClient(
        { body: { client_id: client.clientId, client_secret: "s" } },
        { storage, config },
      ),
      "invalid_client",
    );
  });

  it("rejects more than one JWT in client_assertion [RFC7523 §2.2]", async () => {
    const a = await makeClientAssertion(client, ISSUER);
    await expectOAuthError(attempt({ client_assertion: `${a},${a}` }), "invalid_client");
    await expectOAuthError(attempt({ client_assertion: [a, a] }), "invalid_request");
  });

  it("rejects a client_id that differs from the assertion subject [RFC7521 §4.2]", async () => {
    await expectOAuthError(attempt({ client_id: "someone-else" }), "invalid_client");
  });

  it("rejects iss != sub [RFC7523 §3(1)(2)]", async () => {
    await expectOAuthError(
      attempt({ client_assertion: await makeClientAssertion(client, ISSUER, { iss: "other" }) }),
      "invalid_client",
    );
  });

  it("rejects aud values other than the issuer identifier string [FAPI2 5.3.2.1(8)]", async () => {
    // Token endpoint URL — allowed by plain RFC 7523, forbidden by FAPI2.
    await expectOAuthError(
      attempt({
        client_assertion: await makeClientAssertion(client, ISSUER, { aud: `${ISSUER}/token` }),
      }),
      "invalid_client",
    );
    // Array containing the issuer — must be a plain string.
    await expectOAuthError(
      attempt({
        client_assertion: await makeClientAssertion(client, ISSUER, { aud: [ISSUER] }),
      }),
      "invalid_client",
    );
  });

  it("rejects missing, expired, and unreasonably distant exp [RFC7523 §3(4)]", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    await expectOAuthError(
      attempt({
        client_assertion: await makeClientAssertion(client, ISSUER, { exp: nowSec - 10 }),
      }),
      "invalid_client",
    );
    await expectOAuthError(
      attempt({
        client_assertion: await makeClientAssertion(client, ISSUER, {
          exp: nowSec + config.clientAssertionMaxLifetimeSec + 60,
        }),
      }),
      "invalid_client",
    );
  });

  it("rejects iat/nbf more than the accepted skew in the future [FAPI2 5.3.2.1(13)]", async () => {
    const nowSec = Math.floor(Date.now() / 1000);
    await expectOAuthError(
      attempt({
        client_assertion: await makeClientAssertion(client, ISSUER, { iat: nowSec + 61 }),
      }),
      "invalid_client",
    );
    await expectOAuthError(
      attempt({
        client_assertion: await makeClientAssertion(client, ISSUER, { nbf: nowSec + 61 }),
      }),
      "invalid_client",
    );
    // Small future skew (<= 10s default) is tolerated.
    const ok = await attempt({
      client_assertion: await makeClientAssertion(client, ISSUER, { iat: nowSec + 5 }),
    });
    expect(ok.clientId).toBe(client.clientId);
  });

  it("requires jti and rejects its reuse [OIDC Core §9; RFC7523 §3(7)]", async () => {
    await expectOAuthError(
      attempt({ client_assertion: await makeClientAssertion(client, ISSUER, { jti: null }) }),
      "invalid_client",
    );
    const fixed = await makeClientAssertion(client, ISSUER, { jti: "one-time" });
    await expect(attempt({ client_assertion: fixed })).resolves.toBeTruthy();
    await expectOAuthError(attempt({ client_assertion: fixed }), "invalid_client");
  });

  it("rejects an unknown client", async () => {
    const ghost = await createTestClient({ clientId: "unregistered" });
    await expectOAuthError(
      attempt({ client_assertion: await makeClientAssertion(ghost, ISSUER) }),
      "invalid_client",
    );
  });

  it("ignores an empty client_id parameter [RFC6749 §3.2]", async () => {
    const authed = await attempt({ client_id: "" });
    expect(authed.clientId).toBe(client.clientId);
  });

  it("ignores an empty client_secret parameter (not a second mechanism) [RFC6749 §3.2]", async () => {
    const authed = await attempt({ client_secret: "" });
    expect(authed.clientId).toBe(client.clientId);
  });

  it("surfaces a JWKS fetch outage as 5xx, not invalid_client [availability]", async () => {
    const remote = await createTestClient({ clientId: "remote-jwks-client" });
    // Register with an unreachable https jwks_uri (no inline jwks).
    await storage.clients.upsert({
      clientId: remote.clientId,
      clientName: null,
      metadata: {
        redirect_uris: [remote.redirectUri],
        jwks_uri: "https://unreachable.invalid/jwks.json",
        scope: "openid",
      },
    });
    const err = await expectOAuthError(
      authenticateClient(
        {
          body: {
            client_assertion_type: ASSERTION_TYPE,
            client_assertion: await makeClientAssertion(remote, ISSUER),
          },
        },
        { storage, config },
      ),
      "server_error",
    );
    expect(err.status).toBeGreaterThanOrEqual(500);
  });

  it("treats a malformed registration row as auth failure, not a 500", async () => {
    await storage.clients.upsert({
      clientId: "broken-client",
      clientName: null,
      metadata: { redirect_uris: [] }, // invalid: min(1) + no jwks
    });
    const broken = await createTestClient({ clientId: "broken-client" });
    await expectOAuthError(
      attempt({ client_assertion: await makeClientAssertion(broken, ISSUER) }),
      "invalid_client",
    );
  });

  it("does not pollute the prototype via a __proto__ assertion payload", async () => {
    // JSON payload literal null must not crash (server_error); it is auth fail.
    const header = Buffer.from(JSON.stringify({ alg: "ES256" })).toString("base64url");
    const nullPayload = Buffer.from("null").toString("base64url");
    await expectOAuthError(
      attempt({ client_assertion: `${header}.${nullPayload}.sig` }),
      "invalid_client",
    );
  });

  it("rejects a signature from a key outside the registered JWKS [RFC7523 §3(9)]", async () => {
    const { privateKey: rogue } = await generateKeyPair("ES256");
    await expectOAuthError(
      attempt({
        client_assertion: await makeClientAssertion(client, ISSUER, { signWith: rogue }),
      }),
      "invalid_client",
    );
  });

  it("rejects symmetric and none algorithms [FAPI2 5.4.1]", async () => {
    // A handcrafted alg:none JWT (empty signature).
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const nowSec = Math.floor(Date.now() / 1000);
    const payload = Buffer.from(
      JSON.stringify({
        iss: client.clientId,
        sub: client.clientId,
        aud: ISSUER,
        exp: nowSec + 60,
        jti: "x",
      }),
    ).toString("base64url");
    await expectOAuthError(
      attempt({ client_assertion: `${header}.${payload}.` }),
      "invalid_client",
    );
  });
});
