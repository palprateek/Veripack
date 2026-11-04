-- Server-side dashboard sessions, MFA, and authentication events. Browsers
-- hold only an opaque session id; tokens and TOTP secrets stay encrypted
-- at rest and session ids are stored hashed.

create table if not exists dashboard_sessions (
  id_hash text primary key,
  subject text not null,
  display_name text,
  role text not null default 'publisher',
  encrypted_access_token text not null,
  csrf_secret_hash text not null,
  mfa_level text not null default 'none' check (mfa_level in ('none', 'totp')),
  step_up_deadline timestamptz,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  idle_expires_at timestamptz not null,
  absolute_expires_at timestamptz not null,
  revoked_at timestamptz,
  revocation_reason text
);

create index if not exists dashboard_sessions_subject_idx
  on dashboard_sessions (subject, created_at desc);

create table if not exists dashboard_mfa (
  subject text primary key,
  encrypted_secret text not null,
  recovery_code_hashes jsonb not null default '[]'::jsonb,
  enabled boolean not null default false,
  last_used_step bigint,
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists auth_events (
  id uuid primary key default gen_random_uuid(),
  subject text not null,
  actor text not null,
  action text not null,
  success boolean not null default true,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists auth_events_subject_idx
  on auth_events (subject, created_at desc);

drop trigger if exists auth_events_reject_mutation on auth_events;
create trigger auth_events_reject_mutation
  before update or delete on auth_events
  for each row execute function reject_evidence_mutation();
