-- P1 domain schema: FAPI 2.0 protocol state (docs/REQUIREMENTS-P1.md).
-- Short-lived state carries expires_at; expiry is enforced in queries and
-- expired rows are reaped opportunistically (index on expires_at).

-- ES256 signing keys (NFR-4): DB-backed keystore with rotation via kid
-- status. private_jwk never leaves the keystore (FAPI2-CRYPTO / DISC-7).
create table if not exists signing_keys (
  kid         text primary key,
  alg         text        not null,
  status      text        not null check (status in ('active', 'retired')),
  private_jwk jsonb       not null,
  public_jwk  jsonb       not null,
  created_at  timestamptz not null default now(),
  retired_at  timestamptz
);
-- At most one active key, even across replicas racing on first boot; the
-- keystore retires-before-inserting so rotation never trips this.
create unique index if not exists signing_keys_one_active_idx
  on signing_keys (status) where status = 'active';

-- Pushed authorization requests (RFC 9126). request_uri is client-bound
-- (PAR-5) and one-time use, consumed at authorization action time (PAR-6,
-- FAPI2-AUTHZ-15).
create table if not exists par_requests (
  request_uri text primary key,
  client_id   text        not null references clients (client_id) on delete cascade,
  params      jsonb       not null,
  dpop_jkt    text,
  expires_at  timestamptz not null,
  consumed_at timestamptz
);
create index if not exists par_requests_expires_at_idx on par_requests (expires_at);

-- A grant groups everything issued from one authorization (NFR-1/NFR-3:
-- token management operates per grant; code replay revokes the grant).
-- RESTRICT: deleting a client must not silently erase grant/token/audit
-- state — revoke and reap first (NFR-5).
create table if not exists grants (
  grant_id   uuid primary key,
  client_id  text        not null references clients (client_id) on delete restrict,
  subject    text        not null,
  scope      text        not null,
  auth_time  timestamptz not null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

-- Authorization codes (RFC 6749 §4.1.2): stored hashed, single-use with
-- replay reporting (OAUTH-5), bound to client + redirect_uri, carrying the
-- PKCE association (PKCE-6) and dpop_jkt (DPOP-13).
-- Retention: consumed rows are the replay-detection evidence (RFC 6749
-- §10.5) — any reaper must keep them well past expires_at (e.g. 24h).
create table if not exists authorization_codes (
  code_hash             text primary key,
  grant_id              uuid        not null references grants (grant_id) on delete cascade,
  client_id             text        not null,
  redirect_uri          text        not null,
  code_challenge        text        not null,
  code_challenge_method text        not null,
  dpop_jkt              text,
  nonce                 text,
  expires_at            timestamptz not null,
  consumed_at           timestamptz
);
create index if not exists authorization_codes_expires_at_idx on authorization_codes (expires_at);

-- JWT access tokens are self-contained (RFC 9068); the record (by jti)
-- exists for revocation, introspection, and management (NFR-3).
create table if not exists access_tokens (
  jti        text primary key,
  grant_id   uuid        not null references grants (grant_id) on delete cascade,
  client_id  text        not null,
  subject    text        not null,
  scope      text        not null,
  cnf_jkt    text,
  expires_at timestamptz not null,
  revoked_at timestamptz
);
create index if not exists access_tokens_grant_id_idx on access_tokens (grant_id);
create index if not exists access_tokens_expires_at_idx on access_tokens (expires_at);

-- Refresh tokens: opaque, stored as SHA-256 hashes (OAUTH-12), no rotation
-- (FAPI2-GEN-9), bound to the client via client authentication.
create table if not exists refresh_tokens (
  token_hash text primary key,
  grant_id   uuid        not null references grants (grant_id) on delete cascade,
  client_id  text        not null,
  scope      text        not null,
  expires_at timestamptz not null,
  revoked_at timestamptz
);
create index if not exists refresh_tokens_grant_id_idx on refresh_tokens (grant_id);
create index if not exists refresh_tokens_expires_at_idx on refresh_tokens (expires_at);

-- jti replay guard for client assertions (PKJWT-8) and DPoP proofs (DPOP-6),
-- keyed by usage context so identical jti values in different contexts do
-- not collide.
create table if not exists jti_replay (
  context    text        not null,
  jti        text        not null,
  expires_at timestamptz not null,
  primary key (context, jti)
);
create index if not exists jti_replay_expires_at_idx on jti_replay (expires_at);
