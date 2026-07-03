-- P2 authorization interactions: a parked /authorize request awaiting the
-- user's login + consent. Short-lived; the referenced PAR request_uri is
-- consumed only when the interaction completes (consent approved).
create table if not exists interactions (
  id           text primary key,
  client_id    text        not null references clients (client_id) on delete restrict,
  request_uri  text        not null,
  subject      text,
  auth_time    timestamptz,
  acr          text,
  amr          text[],
  created_at   timestamptz not null default now(),
  completed_at timestamptz,
  expires_at   timestamptz not null
);
create index if not exists interactions_expires_at_idx on interactions (expires_at);
