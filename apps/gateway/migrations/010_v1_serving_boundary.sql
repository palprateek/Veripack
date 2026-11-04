-- Serving boundary: install events, blocklist, Veripack-owned dist-tags, and
-- artifact holds. Install events and blocklist history are append-only.

create table if not exists install_events (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  actor text not null,
  package_name text not null,
  version text,
  tarball_digest text,
  decision text not null check (decision in ('allowed', 'blocked')),
  reason text,
  source text not null check (source in ('packument', 'tarball')),
  request_id text,
  created_at timestamptz not null default now()
);

create index if not exists install_events_org_idx
  on install_events (org_id, created_at desc);

create index if not exists install_events_package_idx
  on install_events (org_id, package_name, created_at desc);

create table if not exists blocklist_entries (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  package_name text not null,
  version text,
  tarball_digest text,
  reason text not null,
  created_by text not null,
  created_at timestamptz not null default now()
);

create index if not exists blocklist_entries_lookup_idx
  on blocklist_entries (org_id, package_name, created_at desc);

create table if not exists blocklist_revocations (
  id uuid primary key default gen_random_uuid(),
  entry_id uuid not null references blocklist_entries(id),
  org_id text not null,
  reason text not null,
  revoked_by text not null,
  created_at timestamptz not null default now()
);

create unique index if not exists blocklist_revocations_entry_key
  on blocklist_revocations (entry_id);

-- Veripack is authoritative for dist-tags; Verdaccio is a mirror.
create table if not exists dist_tags (
  org_id text not null,
  package_name text not null,
  tag text not null,
  version text not null,
  updated_by text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (org_id, package_name, tag)
);

create table if not exists release_artifacts (
  release_id uuid primary key references releases(id) on delete cascade,
  org_id text not null,
  state text not null default 'present' check (state in ('present', 'missing')),
  missing_since timestamptz,
  last_checked_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists release_holds (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  release_id uuid not null references releases(id) on delete cascade,
  reason text not null check (reason in ('artifact_missing')),
  resolution text check (resolution in ('reuploaded', 'rejected')),
  resolved_by text,
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);

create unique index if not exists release_holds_open_idx
  on release_holds (release_id)
  where resolution is null;

create index if not exists release_holds_org_idx
  on release_holds (org_id, created_at desc);

-- Append-only enforcement for install events and blocklist history.
drop trigger if exists install_events_reject_mutation on install_events;
create trigger install_events_reject_mutation
  before update or delete on install_events
  for each row execute function reject_evidence_mutation();

drop trigger if exists blocklist_entries_reject_mutation on blocklist_entries;
create trigger blocklist_entries_reject_mutation
  before update or delete on blocklist_entries
  for each row execute function reject_evidence_mutation();

drop trigger if exists blocklist_revocations_reject_mutation on blocklist_revocations;
create trigger blocklist_revocations_reject_mutation
  before update or delete on blocklist_revocations
  for each row execute function reject_evidence_mutation();
