/**
 * Storage ports for the protocol engine.
 *
 * The domain layer depends only on these interfaces; adapters live in
 * memory.ts (tests / conformance layer 1, Docker-free) and pg.ts (raw SQL on
 * PostgreSQL, the primary store). Protocol decisions (expiry semantics,
 * one-time-use, replay) are enforced HERE atomically where racing matters
 * (code redemption, request_uri consumption, jti replay) so both adapters
 * carry identical semantics.
 */

export interface SigningKeyRecord {
  kid: string;
  alg: "ES256";
  status: "active" | "retired";
  /** Full private JWK (kty/crv/x/y/d). Never exposed via JWKS. */
  privateJwk: Record<string, unknown>;
  publicJwk: Record<string, unknown>;
  createdAt: Date;
  retiredAt: Date | null;
}

export interface SigningKeyRepository {
  list(): Promise<SigningKeyRecord[]>;
  insert(rec: SigningKeyRecord): Promise<void>;
  setStatus(kid: string, status: "active" | "retired", retiredAt: Date | null): Promise<void>;
}

export interface ClientRecord {
  clientId: string;
  clientName: string | null;
  /** Registered client metadata (redirect_uris, jwks, token_endpoint_auth_method, ...). */
  metadata: Record<string, unknown>;
}

export interface ClientRepository {
  findById(clientId: string): Promise<ClientRecord | null>;
  upsert(rec: ClientRecord): Promise<void>;
}

export interface ParRequestRecord {
  /** Full urn:ietf:params:oauth:request_uri:<ref> value (RFC 9126 §2.2). */
  requestUri: string;
  /** RFC 9126 §2.2: the request_uri is bound to the pushing client. */
  clientId: string;
  /** The validated authorization request parameters as pushed. */
  params: Record<string, string>;
  /** RFC 9449 §10.1: DPoP key thumbprint bound at PAR time. */
  dpopJkt: string | null;
  expiresAt: Date;
}

export interface ParRequestRepository {
  insert(rec: ParRequestRecord): Promise<void>;
  /**
   * Non-consuming read of a live (unconsumed, unexpired) pushed request — used
   * at the start of an interaction to validate the request and render consent
   * WITHOUT consuming it (consumption is the authorization action). Null if
   * missing/expired/already consumed.
   */
  peek(requestUri: string, now: Date): Promise<ParRequestRecord | null>;
  /**
   * One-time-use consumption at authorization action time (RFC 9126 §4 /
   * FAPI2-AUTHZ-15). Atomic: returns the record only on first valid use;
   * expired or already-consumed URIs return null.
   */
  consume(requestUri: string, now: Date): Promise<ParRequestRecord | null>;
}

export interface GrantRecord {
  grantId: string;
  clientId: string;
  subject: string;
  scope: string;
  authTime: Date;
  createdAt: Date;
  revokedAt: Date | null;
}

export interface GrantRepository {
  insert(rec: GrantRecord): Promise<void>;
  find(grantId: string): Promise<GrantRecord | null>;
  revoke(grantId: string, at: Date): Promise<void>;
}

export interface AuthorizationCodeRecord {
  /** SHA-256 hash of the code value — the code itself is never stored. */
  codeHash: string;
  grantId: string;
  clientId: string;
  redirectUri: string;
  /** RFC 7636 §4.4: challenge+method are associated with the code. */
  codeChallenge: string;
  codeChallengeMethod: "S256";
  /** RFC 9449 §10: dpop_jkt carried from the authorization request. */
  dpopJkt: string | null;
  nonce: string | null;
  expiresAt: Date;
}

export type CodeRedemption =
  | { status: "ok"; record: AuthorizationCodeRecord }
  /** Previously used — caller must revoke the grant (RFC 6749 §4.1.2 / FAPI2-AUTHZ-9). */
  | { status: "consumed"; record: AuthorizationCodeRecord }
  | { status: "invalid" };

export interface AuthorizationCodeRepository {
  insert(rec: AuthorizationCodeRecord): Promise<void>;
  /** Atomic single-use redemption; reports replay so tokens can be revoked. */
  redeem(codeHash: string, now: Date): Promise<CodeRedemption>;
}

export interface AccessTokenRecord {
  jti: string;
  grantId: string;
  clientId: string;
  subject: string;
  scope: string;
  /** RFC 9449 §6.1 cnf.jkt binding (null only for non-DPoP profiles). */
  cnfJkt: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface AccessTokenRepository {
  insert(rec: AccessTokenRecord): Promise<void>;
  findByJti(jti: string): Promise<AccessTokenRecord | null>;
  revoke(jti: string, at: Date): Promise<void>;
  revokeByGrant(grantId: string, at: Date): Promise<void>;
}

export interface RefreshTokenRecord {
  /** SHA-256 hash of the token value (RFC 6749 §10.4: confidential at rest). */
  tokenHash: string;
  grantId: string;
  clientId: string;
  scope: string;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface RefreshTokenRepository {
  insert(rec: RefreshTokenRecord): Promise<void>;
  findByHash(tokenHash: string): Promise<RefreshTokenRecord | null>;
  revoke(tokenHash: string, at: Date): Promise<void>;
  revokeByGrant(grantId: string, at: Date): Promise<void>;
}

/**
 * A pending authorization interaction (P2): the /authorize request is parked
 * here — referencing the not-yet-consumed PAR request_uri — while the user
 * logs in and consents. Short-lived; the request_uri itself is consumed only
 * when the interaction is completed (consent approved).
 */
export interface InteractionRecord {
  /** Opaque interaction id (carried in the interaction URLs). */
  id: string;
  clientId: string;
  requestUri: string;
  /** Subject once authenticated (null until login completes). */
  subject: string | null;
  authTime: Date | null;
  acr: string | null;
  amr: string[] | null;
  createdAt: Date;
  expiresAt: Date;
}

export interface InteractionRepository {
  insert(rec: InteractionRecord): Promise<void>;
  find(id: string, now: Date): Promise<InteractionRecord | null>;
  /** Attach the authenticated subject after login. */
  setSubject(
    id: string,
    subject: string,
    authTime: Date,
    acr: string | null,
    amr: string[] | null,
  ): Promise<void>;
  /** One-time completion: returns the record only on the first call. */
  complete(id: string, now: Date): Promise<InteractionRecord | null>;
}

export interface JtiReplayRepository {
  /**
   * Register a jti within a context ("client-assertion", "dpop:<htu>").
   * Returns false when the jti was already seen (replay) — RFC 7523 §3(7),
   * RFC 9449 §11.1. Entries expire at expiresAt.
   */
  register(context: string, jti: string, expiresAt: Date, now: Date): Promise<boolean>;
}

export interface Storage {
  keys: SigningKeyRepository;
  clients: ClientRepository;
  par: ParRequestRepository;
  grants: GrantRepository;
  codes: AuthorizationCodeRepository;
  accessTokens: AccessTokenRepository;
  refreshTokens: RefreshTokenRepository;
  jti: JtiReplayRepository;
  interactions: InteractionRepository;
  /** Readiness of the backing store (drives /healthz). */
  ping(): Promise<boolean>;
}
