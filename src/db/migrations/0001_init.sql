-- P0 baseline schema. Establishes the migration path and a representative
-- table. The full domain schema (par_requests / authorization_codes /
-- access_tokens / refresh_tokens / grants / sessions, with TTL columns and
-- indexes) is designed against the specs in P1.

create table if not exists clients (
  client_id   text primary key,
  client_name text,
  -- Registered client metadata: redirect_uris, jwks/jwks_uri,
  -- token_endpoint_auth_method (private_key_jwt), dpop_bound flags, etc.
  metadata    jsonb       not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
