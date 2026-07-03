/**
 * In-memory storage adapter.
 *
 * Backs unit tests and the in-repo conformance layer (Docker-free, no DB —
 * CLAUDE.md CI ループ Layer 1). Semantics mirror the pg adapter exactly:
 * one-time-use consumption, replay reporting, lazy expiry. Rejected in
 * production by loadConfig's fail-closed guard.
 */
import type {
  AccessTokenRecord,
  AccessTokenRepository,
  AuthorizationCodeRecord,
  AuthorizationCodeRepository,
  ClientRecord,
  ClientRepository,
  CodeRedemption,
  GrantRecord,
  GrantRepository,
  JtiReplayRepository,
  ParRequestRecord,
  ParRequestRepository,
  RefreshTokenRecord,
  RefreshTokenRepository,
  SigningKeyRecord,
  SigningKeyRepository,
  Storage,
} from "./types.js";

class MemorySigningKeys implements SigningKeyRepository {
  private readonly rows = new Map<string, SigningKeyRecord>();

  async list(): Promise<SigningKeyRecord[]> {
    return [...this.rows.values()].map((r) => structuredClone(r));
  }

  async insert(rec: SigningKeyRecord): Promise<void> {
    // Mirror the pg partial unique index (signing_keys_one_active_idx) so
    // both adapters exercise the KeyStore race-recovery path identically.
    if (rec.status === "active") {
      for (const row of this.rows.values()) {
        if (row.status === "active") {
          const err = new Error("duplicate active signing key") as Error & { code: string };
          err.code = "23505";
          throw err;
        }
      }
    }
    this.rows.set(rec.kid, structuredClone(rec));
  }

  async setStatus(kid: string, status: "active" | "retired", retiredAt: Date | null): Promise<void> {
    const row = this.rows.get(kid);
    if (row) {
      row.status = status;
      row.retiredAt = retiredAt;
    }
  }
}

class MemoryClients implements ClientRepository {
  private readonly rows = new Map<string, ClientRecord>();

  async findById(clientId: string): Promise<ClientRecord | null> {
    const row = this.rows.get(clientId);
    return row ? structuredClone(row) : null;
  }

  async upsert(rec: ClientRecord): Promise<void> {
    this.rows.set(rec.clientId, structuredClone(rec));
  }
}

class MemoryParRequests implements ParRequestRepository {
  private readonly rows = new Map<string, ParRequestRecord & { consumedAt: Date | null }>();

  async insert(rec: ParRequestRecord): Promise<void> {
    this.rows.set(rec.requestUri, { ...structuredClone(rec), consumedAt: null });
  }

  async consume(requestUri: string, now: Date): Promise<ParRequestRecord | null> {
    const row = this.rows.get(requestUri);
    if (!row || row.consumedAt !== null || row.expiresAt.getTime() <= now.getTime()) {
      return null;
    }
    row.consumedAt = now;
    const { consumedAt: _consumedAt, ...rec } = row;
    return structuredClone(rec);
  }
}

class MemoryGrants implements GrantRepository {
  private readonly rows = new Map<string, GrantRecord>();

  async insert(rec: GrantRecord): Promise<void> {
    this.rows.set(rec.grantId, { ...rec });
  }

  async find(grantId: string): Promise<GrantRecord | null> {
    const row = this.rows.get(grantId);
    return row ? { ...row } : null;
  }

  async revoke(grantId: string, at: Date): Promise<void> {
    const row = this.rows.get(grantId);
    if (row && row.revokedAt === null) row.revokedAt = at;
  }
}

class MemoryAuthorizationCodes implements AuthorizationCodeRepository {
  private readonly rows = new Map<string, AuthorizationCodeRecord & { consumedAt: Date | null }>();

  async insert(rec: AuthorizationCodeRecord): Promise<void> {
    this.rows.set(rec.codeHash, { ...structuredClone(rec), consumedAt: null });
  }

  async redeem(codeHash: string, now: Date): Promise<CodeRedemption> {
    const row = this.rows.get(codeHash);
    if (!row) return { status: "invalid" };
    const { consumedAt, ...record } = row;
    // Replay is reported even after expiry: double use of a consumed code
    // must revoke the grant's tokens (RFC 6749 §4.1.2/§10.5).
    if (consumedAt !== null) return { status: "consumed", record: structuredClone(record) };
    if (row.expiresAt.getTime() <= now.getTime()) return { status: "invalid" };
    row.consumedAt = now;
    return { status: "ok", record: structuredClone(record) };
  }
}

class MemoryAccessTokens implements AccessTokenRepository {
  private readonly rows = new Map<string, AccessTokenRecord>();

  async insert(rec: AccessTokenRecord): Promise<void> {
    this.rows.set(rec.jti, { ...rec });
  }

  async findByJti(jti: string): Promise<AccessTokenRecord | null> {
    const row = this.rows.get(jti);
    return row ? { ...row } : null;
  }

  async revoke(jti: string, at: Date): Promise<void> {
    const row = this.rows.get(jti);
    if (row && row.revokedAt === null) row.revokedAt = at;
  }

  async revokeByGrant(grantId: string, at: Date): Promise<void> {
    for (const row of this.rows.values()) {
      if (row.grantId === grantId && row.revokedAt === null) row.revokedAt = at;
    }
  }
}

class MemoryRefreshTokens implements RefreshTokenRepository {
  private readonly rows = new Map<string, RefreshTokenRecord>();

  async insert(rec: RefreshTokenRecord): Promise<void> {
    this.rows.set(rec.tokenHash, { ...rec });
  }

  async findByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const row = this.rows.get(tokenHash);
    return row ? { ...row } : null;
  }

  async revoke(tokenHash: string, at: Date): Promise<void> {
    const row = this.rows.get(tokenHash);
    if (row && row.revokedAt === null) row.revokedAt = at;
  }

  async revokeByGrant(grantId: string, at: Date): Promise<void> {
    for (const row of this.rows.values()) {
      if (row.grantId === grantId && row.revokedAt === null) row.revokedAt = at;
    }
  }
}

class MemoryJtiReplay implements JtiReplayRepository {
  private readonly rows = new Map<string, Date>();

  private lastSweepMs = 0;

  async register(context: string, jti: string, expiresAt: Date, now: Date): Promise<boolean> {
    // Rate-limited sweep (>=1s apart, only above a size threshold) keeps the
    // map bounded without a timer and without O(n) on every call.
    if (this.rows.size >= 4096 && now.getTime() - this.lastSweepMs >= 1000) {
      this.lastSweepMs = now.getTime();
      for (const [key, exp] of this.rows) {
        if (exp.getTime() <= now.getTime()) this.rows.delete(key);
      }
    }
    // Hard cap fails CLOSED: never evict live entries (that would re-admit a
    // replayed proof); reject new registrations instead. Memory mode is
    // test/dev only -- pg has no such cap.
    if (this.rows.size >= 8192) return false;
    const key = `${context}\u0000${jti}`;
    const existing = this.rows.get(key);
    if (existing && existing.getTime() > now.getTime()) return false;
    this.rows.set(key, expiresAt);
    return true;
  }
}

export function createMemoryStorage(): Storage {
  return {
    keys: new MemorySigningKeys(),
    clients: new MemoryClients(),
    par: new MemoryParRequests(),
    grants: new MemoryGrants(),
    codes: new MemoryAuthorizationCodes(),
    accessTokens: new MemoryAccessTokens(),
    refreshTokens: new MemoryRefreshTokens(),
    jti: new MemoryJtiReplay(),
    ping: async () => true, // in-process store is always ready
  };
}
