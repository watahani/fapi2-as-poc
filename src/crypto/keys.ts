/**
 * ES256 signing keystore (NFR-4).
 *
 * Keys are P-256 JWKs persisted via SigningKeyRepository; the first boot with
 * an empty store generates one (FAPI2-CRYPTO-2/3: ES256, EC P-256 ≥ 224 bit).
 * kid = RFC 7638 SHA-256 JWK thumbprint, so kids are deterministic and never
 * collide across rotations (FAPI2-CRYPTO-5). rotate() introduces a new active
 * key; retired keys stay published until a retention horizon so outstanding
 * signatures verify, then age out of the JWKS (FAPI2-SEC-4).
 *
 * Private keys at rest: when a key-encryption key (KEK) is configured the
 * private JWK is envelope-encrypted with AES-256-GCM before persisting, so a
 * leaked DB dump alone cannot forge tokens. Production requires the KEK
 * (loadConfig fail-closed guard); without one (dev/tests) the JWK is stored
 * as-is.
 *
 * Crash/concurrency safety: the DB rows are written retire-first so the
 * partial unique index in 0002_domain.sql ("at most one active row") never
 * trips during rotation and a crash in between leaves zero active rows
 * (regenerated on next use). In-process, the previous key remains usable for
 * signing until the new key is fully loaded — no 500 window. Losing a
 * concurrent first-boot race surfaces as a unique violation, and the loser
 * adopts the winner's key; any other insert failure propagates.
 *
 * jose is used for primitives only (signing, JWK import/export, thumbprint);
 * everything protocol-level lives in src/domain (docs/ARCHITECTURE.md).
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  type JWTPayload,
  type KeyLike,
} from "jose";
import type { SigningKeyRecord, SigningKeyRepository } from "../db/repositories/types.js";

interface LoadedKey {
  record: SigningKeyRecord;
  privateKey: KeyLike;
}

/** Retired keys stay in the JWKS this long after retirement — comfortably
 * beyond the longest signed-token lifetime (AT/ID ≤ 300s), then drop out so
 * an old key compromise has a closing window. */
const RETIRED_KEY_RETENTION_MS = 24 * 3600 * 1000;

/** Public projection of a stored JWK: EC public members only, never `d`
 * (FAPI2 5.4.2 / DISC-7). Single definition so storage and JWKS agree. */
function toPublicJwk(jwk: Record<string, unknown>): Record<string, unknown> {
  const { kty, crv, x, y, kid, alg, use } = jwk;
  return { kty, crv, x, y, kid, alg, use };
}

interface EncryptedJwk {
  enc: "aes-256-gcm";
  iv: string;
  data: string;
  tag: string;
}

function isEncrypted(v: Record<string, unknown>): v is Record<string, unknown> & EncryptedJwk {
  return v.enc === "aes-256-gcm" && typeof v.data === "string";
}

function encryptJwk(jwk: Record<string, unknown>, kek: Buffer, kid: string): EncryptedJwk {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", kek, iv);
  // kid as AAD binds the ciphertext to its row: swapped blobs fail to open.
  cipher.setAAD(Buffer.from(kid, "utf8"));
  const data = Buffer.concat([cipher.update(JSON.stringify(jwk), "utf8"), cipher.final()]);
  return {
    enc: "aes-256-gcm",
    iv: iv.toString("base64"),
    data: data.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

function decryptJwk(stored: EncryptedJwk, kek: Buffer, kid: string): Record<string, unknown> {
  const decipher = createDecipheriv("aes-256-gcm", kek, Buffer.from(stored.iv, "base64"));
  decipher.setAAD(Buffer.from(kid, "utf8"));
  decipher.setAuthTag(Buffer.from(stored.tag, "base64"));
  const plain = Buffer.concat([
    decipher.update(Buffer.from(stored.data, "base64")),
    decipher.final(),
  ]);
  return JSON.parse(plain.toString("utf8")) as Record<string, unknown>;
}

/** pg unique_violation; the memory adapter mirrors the code so both backends
 * exercise the same race-recovery path. */
function isUniqueViolation(err: unknown): boolean {
  return (err as { code?: unknown } | null)?.code === "23505";
}

export interface KeyStoreOptions {
  /** 32-byte AES-256-GCM key encrypting private JWKs at rest. */
  kek?: Buffer;
  /** Security-warning sink (wired to the app logger). */
  warn?: (msg: string) => void;
}

export class KeyStore {
  private keys = new Map<string, LoadedKey>();
  private active: LoadedKey | undefined;
  private initPromise: Promise<void> | undefined;
  private readonly kek: Buffer | undefined;
  private readonly warn: (msg: string) => void;

  constructor(
    private readonly repo: SigningKeyRepository,
    options: KeyStoreOptions = {},
  ) {
    if (options.kek && options.kek.length !== 32) {
      throw new Error("keystore KEK must be exactly 32 bytes (AES-256-GCM)");
    }
    this.kek = options.kek;
    this.warn = options.warn ?? (() => {});
  }

  /**
   * Memoised lazy init: liveness (/health) must not depend on the DB, so the
   * keystore loads on first use (jwks / signing) instead of at boot; a failed
   * attempt (DB down) is retried on the next request.
   */
  ensure(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.init().catch((err: unknown) => {
        this.initPromise = undefined;
        throw err;
      });
    }
    return this.initPromise;
  }

  /** Load persisted keys; generate the initial active key on first boot. */
  private async init(): Promise<void> {
    const loaded = new Map<string, LoadedKey>();
    for (const record of await this.repo.list()) {
      loaded.set(record.kid, { record, privateKey: await this.importPrivate(record) });
    }
    // Self-heal any historical multi-active state: newest wins, rest retire.
    const actives = [...loaded.values()]
      .filter((k) => k.record.status === "active")
      .sort((a, b) => a.record.createdAt.getTime() - b.record.createdAt.getTime());
    for (const stale of actives.slice(0, -1)) {
      stale.record.status = "retired";
      stale.record.retiredAt = new Date();
      await this.repo.setStatus(stale.record.kid, "retired", stale.record.retiredAt);
    }
    // Atomic swap: a racing publicJwks() never sees a partially-built map.
    this.keys = loaded;
    this.active = actives.at(-1);
    if (!this.active) {
      await this.rotate();
    }
  }

  /** Retire the current key and generate a new active P-256 key. The old key
   * keeps signing in-process until the new one is fully persisted+loaded. */
  async rotate(): Promise<string> {
    const previous = this.active;
    if (previous) {
      // DB rows go retire-first so the one-active unique index never trips;
      // this.active intentionally still points at the old key so concurrent
      // signJwt() calls keep working (its signatures verify via the JWKS,
      // where it stays published as retired).
      previous.record.status = "retired";
      previous.record.retiredAt = new Date();
      await this.repo.setStatus(previous.record.kid, "retired", previous.record.retiredAt);
    }

    const { privateKey } = await generateKeyPair("ES256", { extractable: true });
    const privateJwk = (await exportJWK(privateKey)) as unknown as Record<string, unknown>;
    const kid = await calculateJwkThumbprint(toPublicJwk(privateJwk) as unknown as JWK, "sha256");
    const stamped = { ...privateJwk, kid, alg: "ES256", use: "sig" };
    const record: SigningKeyRecord = {
      kid,
      alg: "ES256",
      status: "active",
      privateJwk: this.kek
        ? (encryptJwk(stamped, this.kek, kid) as unknown as Record<string, unknown>)
        : stamped,
      publicJwk: toPublicJwk(stamped),
      createdAt: new Date(),
      retiredAt: null,
    };
    try {
      await this.repo.insert(record);
    } catch (err) {
      // Only a one-active unique violation means "a concurrent boot won the
      // race" — adopt the winner. Anything else is a real failure; the old
      // key remains active in-process so signing stays available.
      if (!isUniqueViolation(err)) throw err;
      const records = await this.repo.list();
      const winner = records.find((r) => r.status === "active");
      if (!winner) throw err;
      const adopted = { record: winner, privateKey: await this.importPrivate(winner) };
      this.keys.set(winner.kid, adopted);
      this.active = adopted;
      return winner.kid;
    }
    this.keys.set(kid, { record, privateKey: privateKey as KeyLike });
    this.active = this.keys.get(kid);
    return kid;
  }

  activeKid(): string {
    return this.mustActive().record.kid;
  }

  /** Public JWKS (RFC 7517): active key first; retired keys published until
   * the retention horizon so outstanding signatures verify, then dropped.
   * Never contains private material. */
  publicJwks(now: Date = new Date()): { keys: Record<string, unknown>[] } {
    const records = [...this.keys.values()]
      .map((k) => k.record)
      .filter(
        (r) =>
          r.status === "active" ||
          r.retiredAt === null ||
          now.getTime() - r.retiredAt.getTime() < RETIRED_KEY_RETENTION_MS,
      )
      .sort((a, b) => Number(b.status === "active") - Number(a.status === "active"));
    return { keys: records.map((r) => toPublicJwk(r.publicJwk)) };
  }

  /** Sign a JWT with the active ES256 key. `typ` distinguishes token types
   * (at+jwt for access tokens per JWTAT-1; unset = JWT for ID tokens). */
  async signJwt(payload: JWTPayload, opts: { typ?: string } = {}): Promise<string> {
    const { record, privateKey } = this.mustActive();
    return new SignJWT(payload)
      .setProtectedHeader({ alg: "ES256", kid: record.kid, ...(opts.typ ? { typ: opts.typ } : {}) })
      .sign(privateKey);
  }

  private async importPrivate(record: SigningKeyRecord): Promise<KeyLike> {
    let jwk = record.privateJwk;
    if (isEncrypted(jwk)) {
      if (!this.kek) {
        throw new Error(`signing key ${record.kid} is encrypted but no KEYSTORE_KEK is configured`);
      }
      jwk = decryptJwk(jwk, this.kek, record.kid);
      if (jwk.kid !== record.kid) {
        throw new Error(`signing key ${record.kid}: decrypted JWK kid mismatch`);
      }
    } else if (this.kek) {
      // Plaintext row in a KEK-enabled deployment (key predates the KEK):
      // usable, but the at-rest guarantee does not hold — surface it loudly;
      // rotating re-persists encrypted.
      this.warn(`signing key ${record.kid} is stored UNENCRYPTED despite KEYSTORE_KEK — rotate it`);
    }
    return (await importJWK(jwk as unknown as JWK, "ES256")) as KeyLike;
  }

  private mustActive(): LoadedKey {
    if (!this.active) throw new Error("keystore not initialised (await ensure() first)");
    return this.active;
  }
}
