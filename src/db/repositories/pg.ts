/**
 * PostgreSQL storage adapter (raw SQL via pg — no ORM, per docs/GOALS.md).
 * Schema: src/db/migrations/0002_domain.sql. Where single-use semantics
 * matter (request_uri consumption, code redemption, jti replay) the check
 * and the write happen in one statement so concurrent requests cannot both
 * succeed.
 */
import type pg from "pg";
import { pingDb } from "../pool.js";
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

class PgSigningKeys implements SigningKeyRepository {
  constructor(private readonly pool: pg.Pool) {}

  async list(): Promise<SigningKeyRecord[]> {
    const res = await this.pool.query(
      `select kid, alg, status, private_jwk, public_jwk, created_at, retired_at
         from signing_keys order by created_at`,
    );
    return res.rows.map((r) => ({
      kid: r.kid,
      alg: r.alg,
      status: r.status,
      privateJwk: r.private_jwk,
      publicJwk: r.public_jwk,
      createdAt: r.created_at,
      retiredAt: r.retired_at,
    }));
  }

  async insert(rec: SigningKeyRecord): Promise<void> {
    await this.pool.query(
      `insert into signing_keys (kid, alg, status, private_jwk, public_jwk, created_at, retired_at)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [rec.kid, rec.alg, rec.status, rec.privateJwk, rec.publicJwk, rec.createdAt, rec.retiredAt],
    );
  }

  async setStatus(kid: string, status: "active" | "retired", retiredAt: Date | null): Promise<void> {
    await this.pool.query(`update signing_keys set status = $2, retired_at = $3 where kid = $1`, [
      kid,
      status,
      retiredAt,
    ]);
  }
}

class PgClients implements ClientRepository {
  constructor(private readonly pool: pg.Pool) {}

  async findById(clientId: string): Promise<ClientRecord | null> {
    const res = await this.pool.query(
      `select client_id, client_name, metadata from clients where client_id = $1`,
      [clientId],
    );
    const row = res.rows[0];
    return row
      ? { clientId: row.client_id, clientName: row.client_name, metadata: row.metadata }
      : null;
  }

  async upsert(rec: ClientRecord): Promise<void> {
    await this.pool.query(
      `insert into clients (client_id, client_name, metadata)
       values ($1, $2, $3)
       on conflict (client_id)
       do update set client_name = excluded.client_name,
                     metadata = excluded.metadata,
                     updated_at = now()`,
      [rec.clientId, rec.clientName, rec.metadata],
    );
  }
}

class PgParRequests implements ParRequestRepository {
  constructor(private readonly pool: pg.Pool) {}

  async insert(rec: ParRequestRecord): Promise<void> {
    await this.pool.query(
      `insert into par_requests (request_uri, client_id, params, dpop_jkt, expires_at)
       values ($1, $2, $3, $4, $5)`,
      [rec.requestUri, rec.clientId, rec.params, rec.dpopJkt, rec.expiresAt],
    );
  }

  async consume(requestUri: string, now: Date): Promise<ParRequestRecord | null> {
    // Atomic one-time use (PAR-6): only the first caller gets the row.
    const res = await this.pool.query(
      `update par_requests
          set consumed_at = $2
        where request_uri = $1 and consumed_at is null and expires_at > $2
        returning request_uri, client_id, params, dpop_jkt, expires_at`,
      [requestUri, now],
    );
    const row = res.rows[0];
    return row
      ? {
          requestUri: row.request_uri,
          clientId: row.client_id,
          params: row.params,
          dpopJkt: row.dpop_jkt,
          expiresAt: row.expires_at,
        }
      : null;
  }
}

class PgGrants implements GrantRepository {
  constructor(private readonly pool: pg.Pool) {}

  async insert(rec: GrantRecord): Promise<void> {
    await this.pool.query(
      `insert into grants (grant_id, client_id, subject, scope, auth_time, created_at, revoked_at)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [rec.grantId, rec.clientId, rec.subject, rec.scope, rec.authTime, rec.createdAt, rec.revokedAt],
    );
  }

  async find(grantId: string): Promise<GrantRecord | null> {
    const res = await this.pool.query(
      `select grant_id, client_id, subject, scope, auth_time, created_at, revoked_at
         from grants where grant_id = $1`,
      [grantId],
    );
    const row = res.rows[0];
    return row
      ? {
          grantId: row.grant_id,
          clientId: row.client_id,
          subject: row.subject,
          scope: row.scope,
          authTime: row.auth_time,
          createdAt: row.created_at,
          revokedAt: row.revoked_at,
        }
      : null;
  }

  async revoke(grantId: string, at: Date): Promise<void> {
    await this.pool.query(
      `update grants set revoked_at = $2 where grant_id = $1 and revoked_at is null`,
      [grantId, at],
    );
  }
}

function codeRowToRecord(row: Record<string, unknown>): AuthorizationCodeRecord {
  return {
    codeHash: row.code_hash as string,
    grantId: row.grant_id as string,
    clientId: row.client_id as string,
    redirectUri: row.redirect_uri as string,
    codeChallenge: row.code_challenge as string,
    codeChallengeMethod: row.code_challenge_method as "S256",
    dpopJkt: row.dpop_jkt as string | null,
    nonce: row.nonce as string | null,
    expiresAt: row.expires_at as Date,
  };
}

class PgAuthorizationCodes implements AuthorizationCodeRepository {
  constructor(private readonly pool: pg.Pool) {}

  async insert(rec: AuthorizationCodeRecord): Promise<void> {
    await this.pool.query(
      `insert into authorization_codes
         (code_hash, grant_id, client_id, redirect_uri, code_challenge,
          code_challenge_method, dpop_jkt, nonce, expires_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        rec.codeHash,
        rec.grantId,
        rec.clientId,
        rec.redirectUri,
        rec.codeChallenge,
        rec.codeChallengeMethod,
        rec.dpopJkt,
        rec.nonce,
        rec.expiresAt,
      ],
    );
  }

  async redeem(codeHash: string, now: Date): Promise<CodeRedemption> {
    // Single-use with replay reporting (OAUTH-5 / FAPI2-AUTHZ-9): the UPDATE
    // only succeeds for the first redemption (row lock serialises racers);
    // losers fall through to the SELECT and are reported as replay so the
    // caller can revoke the grant.
    const upd = await this.pool.query(
      `update authorization_codes
          set consumed_at = $2
        where code_hash = $1 and consumed_at is null and expires_at > $2
        returning *`,
      [codeHash, now],
    );
    if (upd.rows[0]) return { status: "ok", record: codeRowToRecord(upd.rows[0]) };
    // Replay is reported regardless of expiry: a consumed code presented
    // again — even late — is double use and must revoke the grant's tokens
    // (RFC 6749 §4.1.2/§10.5).
    const sel = await this.pool.query(
      `select * from authorization_codes where code_hash = $1 and consumed_at is not null`,
      [codeHash],
    );
    if (sel.rows[0]) return { status: "consumed", record: codeRowToRecord(sel.rows[0]) };
    return { status: "invalid" };
  }
}

class PgAccessTokens implements AccessTokenRepository {
  constructor(private readonly pool: pg.Pool) {}

  async insert(rec: AccessTokenRecord): Promise<void> {
    await this.pool.query(
      `insert into access_tokens (jti, grant_id, client_id, subject, scope, cnf_jkt, expires_at, revoked_at)
       values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [rec.jti, rec.grantId, rec.clientId, rec.subject, rec.scope, rec.cnfJkt, rec.expiresAt, rec.revokedAt],
    );
  }

  async findByJti(jti: string): Promise<AccessTokenRecord | null> {
    const res = await this.pool.query(
      `select jti, grant_id, client_id, subject, scope, cnf_jkt, expires_at, revoked_at
         from access_tokens where jti = $1`,
      [jti],
    );
    const row = res.rows[0];
    return row
      ? {
          jti: row.jti,
          grantId: row.grant_id,
          clientId: row.client_id,
          subject: row.subject,
          scope: row.scope,
          cnfJkt: row.cnf_jkt,
          expiresAt: row.expires_at,
          revokedAt: row.revoked_at,
        }
      : null;
  }

  async revoke(jti: string, at: Date): Promise<void> {
    await this.pool.query(
      `update access_tokens set revoked_at = $2 where jti = $1 and revoked_at is null`,
      [jti, at],
    );
  }

  async revokeByGrant(grantId: string, at: Date): Promise<void> {
    await this.pool.query(
      `update access_tokens set revoked_at = $2 where grant_id = $1 and revoked_at is null`,
      [grantId, at],
    );
  }
}

class PgRefreshTokens implements RefreshTokenRepository {
  constructor(private readonly pool: pg.Pool) {}

  async insert(rec: RefreshTokenRecord): Promise<void> {
    await this.pool.query(
      `insert into refresh_tokens (token_hash, grant_id, client_id, scope, expires_at, revoked_at)
       values ($1, $2, $3, $4, $5, $6)`,
      [rec.tokenHash, rec.grantId, rec.clientId, rec.scope, rec.expiresAt, rec.revokedAt],
    );
  }

  async findByHash(tokenHash: string): Promise<RefreshTokenRecord | null> {
    const res = await this.pool.query(
      `select token_hash, grant_id, client_id, scope, expires_at, revoked_at
         from refresh_tokens where token_hash = $1`,
      [tokenHash],
    );
    const row = res.rows[0];
    return row
      ? {
          tokenHash: row.token_hash,
          grantId: row.grant_id,
          clientId: row.client_id,
          scope: row.scope,
          expiresAt: row.expires_at,
          revokedAt: row.revoked_at,
        }
      : null;
  }

  async revoke(tokenHash: string, at: Date): Promise<void> {
    await this.pool.query(
      `update refresh_tokens set revoked_at = $2 where token_hash = $1 and revoked_at is null`,
      [tokenHash, at],
    );
  }

  async revokeByGrant(grantId: string, at: Date): Promise<void> {
    await this.pool.query(
      `update refresh_tokens set revoked_at = $2 where grant_id = $1 and revoked_at is null`,
      [grantId, at],
    );
  }
}

class PgJtiReplay implements JtiReplayRepository {
  constructor(private readonly pool: pg.Pool) {}

  async register(context: string, jti: string, expiresAt: Date, now: Date): Promise<boolean> {
    // Probabilistic reap (~1% of calls) keeps the table bounded without a
    // background job while staying off the hot path (NFR-7); a periodic job
    // can replace this later.
    if (Math.random() < 0.01) {
      await this.pool.query(
        `delete from jti_replay where ctid in
           (select ctid from jti_replay where expires_at <= $1 limit 1000)`,
        [now],
      );
    }
    // An expired row must not count as replay (mirrors the memory adapter):
    // the conditional DO UPDATE claims the slot iff the old entry expired, so
    // rowCount=1 means inserted-or-reclaimed and 0 means live conflict.
    const res = await this.pool.query(
      `insert into jti_replay (context, jti, expires_at)
       values ($1, $2, $3)
       on conflict (context, jti) do update set expires_at = excluded.expires_at
       where jti_replay.expires_at <= $4`,
      [context, jti, expiresAt, now],
    );
    return res.rowCount === 1;
  }
}

export function createPgStorage(pool: pg.Pool): Storage {
  return {
    keys: new PgSigningKeys(pool),
    clients: new PgClients(pool),
    par: new PgParRequests(pool),
    grants: new PgGrants(pool),
    codes: new PgAuthorizationCodes(pool),
    accessTokens: new PgAccessTokens(pool),
    refreshTokens: new PgRefreshTokens(pool),
    jti: new PgJtiReplay(pool),
    ping: () => pingDb(pool),
  };
}
