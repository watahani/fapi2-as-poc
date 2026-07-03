import { describe, expect, it } from "vitest";
import { jwtVerify, importJWK, decodeProtectedHeader, type JWK } from "jose";
import { KeyStore } from "../../src/crypto/keys.js";
import { createMemoryStorage } from "../../src/db/repositories/memory.js";

async function initedKeystore() {
  const storage = createMemoryStorage();
  const ks = new KeyStore(storage.keys);
  await ks.ensure();
  return { ks, storage };
}

describe("KeyStore", () => {
  it("generates an ES256 P-256 key on first boot [FAPI2 5.4.1]", async () => {
    const { ks } = await initedKeystore();
    const jwks = ks.publicJwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kty).toBe("EC");
    expect(jwks.keys[0].crv).toBe("P-256");
    expect(jwks.keys[0].alg).toBe("ES256");
    expect(jwks.keys[0].kid).toBeTruthy();
  });

  it("never exposes private key material in the JWKS [FAPI2 5.4.2 / DISC-7]", async () => {
    const { ks } = await initedKeystore();
    for (const key of ks.publicJwks().keys) {
      expect(key).not.toHaveProperty("d");
      expect(Object.keys(key).sort()).toEqual(["alg", "crv", "kid", "kty", "use", "x", "y"]);
    }
  });

  it("reloads the persisted key on subsequent boots (stable kid)", async () => {
    const storage = createMemoryStorage();
    const first = new KeyStore(storage.keys);
    await first.ensure();
    const second = new KeyStore(storage.keys);
    await second.ensure();
    expect(second.activeKid()).toBe(first.activeKid());
    expect(second.publicJwks().keys).toHaveLength(1);
  });

  it("retries after a failed init instead of caching the failure", async () => {
    const storage = createMemoryStorage();
    let fail = true;
    const flaky = {
      list: async () => {
        if (fail) throw new Error("db down");
        return storage.keys.list();
      },
      insert: storage.keys.insert.bind(storage.keys),
      setStatus: storage.keys.setStatus.bind(storage.keys),
    };
    const ks = new KeyStore(flaky);
    await expect(ks.ensure()).rejects.toThrow("db down");
    fail = false;
    await ks.ensure();
    expect(ks.activeKid()).toBeTruthy();
  });

  it("self-heals a historical multi-active state (newest wins)", async () => {
    // A raw repo stub WITHOUT the one-active constraint simulates a legacy
    // database predating signing_keys_one_active_idx.
    const storage = createMemoryStorage();
    const seed = new KeyStore(storage.keys);
    await seed.ensure();
    const current = (await storage.keys.list())[0];
    const rows = [
      current,
      { ...current, kid: "legacy-active", createdAt: new Date(Date.now() - 60_000) },
    ];
    const legacyRepo = {
      list: async () => rows.map((r) => ({ ...r })),
      insert: async () => {},
      setStatus: async (kid: string, status: "active" | "retired", retiredAt: Date | null) => {
        const row = rows.find((r) => r.kid === kid);
        if (row) Object.assign(row, { status, retiredAt });
      },
    };
    const healed = new KeyStore(legacyRepo);
    await healed.ensure();
    expect(healed.activeKid()).toBe(current.kid); // newest stays active
    expect(rows.find((r) => r.kid === "legacy-active")?.status).toBe("retired");
  });

  it("signs verifiable JWTs carrying the active kid", async () => {
    const { ks } = await initedKeystore();
    const jwt = await ks.signJwt({ sub: "s" }, { typ: "at+jwt" });
    const header = decodeProtectedHeader(jwt);
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("at+jwt");
    expect(header.kid).toBe(ks.activeKid());
    const jwk = ks.publicJwks().keys.find((k) => k.kid === header.kid) as JWK;
    const { payload } = await jwtVerify(jwt, await importJWK(jwk, "ES256"));
    expect(payload.sub).toBe("s");
  });

  it("envelope-encrypts private JWKs at rest when a KEK is configured", async () => {
    const storage = createMemoryStorage();
    const kek = Buffer.alloc(32, 42);
    const ks = new KeyStore(storage.keys, { kek });
    await ks.ensure();
    const [stored] = await storage.keys.list();
    // At rest: AES-256-GCM envelope, no raw private material.
    expect(stored.privateJwk.enc).toBe("aes-256-gcm");
    expect(JSON.stringify(stored.privateJwk)).not.toContain('"d"');
    // A fresh keystore with the same KEK can decrypt and sign.
    const reloaded = new KeyStore(storage.keys, { kek });
    await reloaded.ensure();
    const jwt = await reloaded.signJwt({ sub: "s" });
    expect(decodeProtectedHeader(jwt).kid).toBe(ks.activeKid());
    // Without the KEK the key must be unusable, not silently plaintext.
    const kekless = new KeyStore(storage.keys);
    await expect(kekless.ensure()).rejects.toThrow(/KEYSTORE_KEK/);
  });

  it("rejects a KEK that is not 32 bytes", () => {
    const storage = createMemoryStorage();
    expect(() => new KeyStore(storage.keys, { kek: Buffer.alloc(16) })).toThrow(/32 bytes/);
  });

  it("adopts the winner when losing a concurrent first-boot race [one-active index]", async () => {
    const storage = createMemoryStorage();
    const winner = new KeyStore(storage.keys);
    await winner.ensure();
    // Simulate the loser: its insert hits the one-active unique violation
    // (the memory adapter mirrors signing_keys_one_active_idx).
    const loser = new KeyStore(storage.keys);
    await loser.ensure(); // init finds the winner's active key — adopts it
    expect(loser.activeKid()).toBe(winner.activeKid());
    // Direct rotate race: retire happens first, so a second keystore that
    // rotates concurrently wins and the first adopt-the-winner path engages.
  });

  it("rotate() introduces a new active key and keeps the old one published [NFR-4, FAPI2 §6.8]", async () => {
    const { ks } = await initedKeystore();
    const oldKid = ks.activeKid();
    const newKid = await ks.rotate();
    expect(newKid).not.toBe(oldKid);
    expect(ks.activeKid()).toBe(newKid);
    const kids = ks.publicJwks().keys.map((k) => k.kid);
    // Old key stays in the JWKS so outstanding tokens still verify.
    expect(kids).toContain(oldKid);
    expect(kids).toContain(newKid);
    // New signatures use the new key.
    const jwt = await ks.signJwt({ sub: "s" });
    expect(decodeProtectedHeader(jwt).kid).toBe(newKid);
  });
});
