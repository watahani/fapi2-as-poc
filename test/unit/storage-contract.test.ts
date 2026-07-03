/**
 * Storage contract test: the SAME protocol semantics must hold for every
 * adapter (types.ts contract). Always runs against the memory adapter;
 * additionally runs against PostgreSQL when PG_TEST_URL is set (CI provides
 * a service container; locally point it at the k3s dev postgres).
 */
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";
import { createPgStorage } from "../../src/db/repositories/pg.js";
import { runMigrations } from "../../src/db/migrate.js";
import type {
  AuthorizationCodeRecord,
  ParRequestRecord,
  Storage,
} from "../../src/db/repositories/types.js";

const now = () => new Date();
const later = (sec: number) => new Date(Date.now() + sec * 1000);

interface Backend {
  name: string;
  storage: () => Storage;
  cleanup?: () => Promise<void>;
}

const backends: Backend[] = [{ name: "memory", storage: () => createMemoryStorage() }];

const pgUrl = process.env.PG_TEST_URL;
let pgPool: pg.Pool | undefined;
if (pgUrl) {
  pgPool = new pg.Pool({ connectionString: pgUrl, max: 5 });
  await runMigrations(pgPool);
  backends.push({ name: "postgres", storage: () => createPgStorage(pgPool as pg.Pool) });
}

afterAll(async () => {
  await pgPool?.end();
});

describe.each(backends)("storage contract ($name)", ({ name, storage }) => {
  let s: Storage;
  // Unique per-test IDs so the pg backend needs no truncation between tests.
  let uri: string;
  let codeHash: string;
  let grantId: string;
  const clientId = "contract-test-client";

  beforeEach(async () => {
    s = storage();
    uri = `urn:ietf:params:oauth:request_uri:${randomUUID()}`;
    codeHash = randomUUID();
    grantId = randomUUID();
    await s.clients.upsert({ clientId, clientName: null, metadata: {} });
    await s.grants.insert({
      grantId,
      clientId,
      subject: "user-1",
      scope: "openid",
      authTime: now(),
      createdAt: now(),
      revokedAt: null,
    });
  });

  const parRecord = (over: Partial<ParRequestRecord> = {}): ParRequestRecord => ({
    requestUri: uri,
    clientId,
    params: { response_type: "code" },
    dpopJkt: null,
    expiresAt: later(90),
    ...over,
  });

  const codeRecord = (over: Partial<AuthorizationCodeRecord> = {}): AuthorizationCodeRecord => ({
    codeHash,
    grantId,
    clientId,
    redirectUri: "https://c.example/cb",
    codeChallenge: "x".repeat(43),
    codeChallengeMethod: "S256",
    dpopJkt: null,
    nonce: null,
    expiresAt: later(60),
    ...over,
  });

  it("ping() reports readiness", async () => {
    expect(await s.ping()).toBe(true);
  });

  describe("signing keys", () => {
    it("rejects a second active key with a unique violation [signing_keys_one_active_idx]", async () => {
      const key = (kid: string, status: "active" | "retired") => ({
        kid,
        alg: "ES256" as const,
        status,
        privateJwk: { kty: "EC" },
        publicJwk: { kty: "EC" },
        createdAt: now(),
        retiredAt: status === "retired" ? now() : null,
      });
      const a = randomUUID();
      const b = randomUUID();
      await s.keys.insert(key(a, "active"));
      await expect(s.keys.insert(key(b, "active"))).rejects.toMatchObject({ code: "23505" });
      // Retiring the active key frees the slot.
      await s.keys.setStatus(a, "retired", now());
      await expect(s.keys.insert(key(b, "active"))).resolves.toBeUndefined();
      await s.keys.setStatus(b, "retired", now()); // leave no active behind (pg is shared)
    });
  });

  describe("PAR requests", () => {
    it("consume() is one-time use [RFC9126 §4 / PAR-6]", async () => {
      await s.par.insert(parRecord());
      const first = await s.par.consume(uri, now());
      expect(first?.clientId).toBe(clientId);
      expect(first?.params).toEqual({ response_type: "code" });
      expect(await s.par.consume(uri, now())).toBeNull();
    });

    it("consume() rejects expired request URIs [RFC9126 §4 / PAR-7]", async () => {
      await s.par.insert(parRecord({ expiresAt: later(-1) }));
      expect(await s.par.consume(uri, now())).toBeNull();
    });

    it("consume() rejects unknown request URIs", async () => {
      expect(await s.par.consume(`urn:ietf:params:oauth:request_uri:${randomUUID()}`, now())).toBeNull();
    });
  });

  describe("authorization codes", () => {
    it("redeem() succeeds once, then reports replay [RFC6749 §4.1.2 / OAUTH-5]", async () => {
      await s.codes.insert(codeRecord());
      expect((await s.codes.redeem(codeHash, now())).status).toBe("ok");
      const replay = await s.codes.redeem(codeHash, now());
      expect(replay.status).toBe("consumed");
      if (replay.status === "consumed") {
        // Replay reporting carries the grant so the caller can revoke it.
        expect(replay.record.grantId).toBe(grantId);
      }
    });

    it("redeem() reports replay of a consumed code even after expiry [RFC6749 §10.5]", async () => {
      await s.codes.insert(codeRecord({ expiresAt: later(1) }));
      expect((await s.codes.redeem(codeHash, now())).status).toBe("ok");
      expect((await s.codes.redeem(codeHash, later(2))).status).toBe("consumed");
    });

    it("redeem() treats expired unredeemed codes as invalid", async () => {
      await s.codes.insert(codeRecord({ expiresAt: later(-1) }));
      expect((await s.codes.redeem(codeHash, now())).status).toBe("invalid");
    });

    it("redeem() treats unknown codes as invalid", async () => {
      expect((await s.codes.redeem(randomUUID(), now())).status).toBe("invalid");
    });
  });

  describe("jti replay guard", () => {
    it("rejects a duplicate jti within its window [RFC7523 §3(7) / RFC9449 §11.1]", async () => {
      const jti = randomUUID();
      expect(await s.jti.register("client-assertion", jti, later(300), now())).toBe(true);
      expect(await s.jti.register("client-assertion", jti, later(300), now())).toBe(false);
    });

    it("scopes jti values per context", async () => {
      const jti = randomUUID();
      expect(await s.jti.register("client-assertion", jti, later(300), now())).toBe(true);
      expect(await s.jti.register("dpop:https://as/token", jti, later(300), now())).toBe(true);
    });

    it("allows reuse after expiry", async () => {
      const jti = randomUUID();
      expect(await s.jti.register("client-assertion", jti, later(-1), now())).toBe(true);
      expect(await s.jti.register("client-assertion", jti, later(300), now())).toBe(true);
    });
  });

  describe("grant-scoped revocation", () => {
    it("revokeByGrant() revokes all tokens of the grant [NFR-1/NFR-3]", async () => {
      const jti = randomUUID();
      const rtHash = randomUUID();
      await s.accessTokens.insert({
        jti,
        grantId,
        clientId,
        subject: "user-1",
        scope: "openid",
        cnfJkt: "jkt",
        expiresAt: later(300),
        revokedAt: null,
      });
      await s.refreshTokens.insert({
        tokenHash: rtHash,
        grantId,
        clientId,
        scope: "openid",
        expiresAt: later(3600),
        revokedAt: null,
      });
      const at = now();
      await s.accessTokens.revokeByGrant(grantId, at);
      await s.refreshTokens.revokeByGrant(grantId, at);
      expect((await s.accessTokens.findByJti(jti))?.revokedAt).not.toBeNull();
      expect((await s.refreshTokens.findByHash(rtHash))?.revokedAt).not.toBeNull();
    });

    it("grants.revoke() stamps revoked_at once", async () => {
      await s.grants.revoke(grantId, now());
      const g = await s.grants.find(grantId);
      expect(g?.revokedAt).not.toBeNull();
    });
  });

  describe("interactions (P2 pending authorization)", () => {
    const mk = (over: Record<string, unknown> = {}) => ({
      id: randomUUID(),
      clientId,
      requestUri: `urn:ietf:params:oauth:request_uri:${randomUUID()}`,
      subject: null,
      authTime: null,
      acr: null,
      amr: null,
      createdAt: now(),
      expiresAt: later(600),
      ...over,
    });

    it("finds a live interaction and hides expired/unknown ones", async () => {
      const rec = mk();
      await s.interactions.insert(rec);
      expect((await s.interactions.find(rec.id, now()))?.requestUri).toBe(rec.requestUri);
      expect(await s.interactions.find(randomUUID(), now())).toBeNull();
      const expired = mk({ expiresAt: later(-1) });
      await s.interactions.insert(expired);
      expect(await s.interactions.find(expired.id, now())).toBeNull();
    });

    it("attaches the authenticated subject", async () => {
      const rec = mk();
      await s.interactions.insert(rec);
      await s.interactions.setSubject(rec.id, "user-9", now(), "urn:dev:pwd", ["pwd"]);
      const loaded = await s.interactions.find(rec.id, now());
      expect(loaded?.subject).toBe("user-9");
      expect(loaded?.acr).toBe("urn:dev:pwd");
      expect(loaded?.amr).toEqual(["pwd"]);
    });

    it("complete() is one-time", async () => {
      const rec = mk({ subject: "user-1", authTime: now() });
      await s.interactions.insert(rec);
      expect((await s.interactions.complete(rec.id, now()))?.subject).toBe("user-1");
      expect(await s.interactions.complete(rec.id, now())).toBeNull();
      // A completed interaction is no longer findable.
      expect(await s.interactions.find(rec.id, now())).toBeNull();
    });
  });

  // `name` intentionally referenced so vitest prints the backend in failures.
  it(`runs against ${name}`, () => expect(true).toBe(true));
});
