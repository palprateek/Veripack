create table if not exists releases (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  package_name text not null,
  version text not null,
  tarball_digest text not null,
  tarball_key text not null,
  tarball_filename text not null,
  payload_key text not null,
  integrity text,
  shasum text,
  status text not null default 'pending',
  publisher text not null,
  intent text,
  manifest jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint releases_status_check check (
    status in ('pending', 'approved', 'rejected', 'yanked', 'quarantined', 'overridden')
  ),
  constraint releases_org_package_version_key unique (org_id, package_name, version)
);

create index if not exists releases_package_idx
  on releases (org_id, package_name, created_at desc);

create index if not exists releases_status_idx
  on releases (org_id, status, created_at desc);

create index if not exists releases_tarball_idx
  on releases (org_id, package_name, tarball_filename);

create table if not exists audits (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  release_id uuid not null references releases(id) on delete cascade,
  engine_version text not null,
  safety_verdict text not null,
  intent_verdict text not null,
  risk_tier text not null,
  policy_result text not null,
  signals jsonb not null default '[]'::jsonb,
  change_set jsonb not null default '{}'::jsonb,
  summary text,
  started_at timestamptz not null,
  finished_at timestamptz not null,
  created_at timestamptz not null default now(),
  constraint audits_release_key unique (release_id)
);

create index if not exists audits_release_idx on audits (release_id);

create table if not exists approvals (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  release_id uuid not null references releases(id) on delete cascade,
  reviewer_id text not null,
  reviewer_type text not null check (reviewer_type in ('human', 'agent', 'system')),
  decision text not null check (
    decision in ('approved', 'rejected', 'yanked', 'quarantined', 'overridden')
  ),
  reason text,
  policy_version text,
  created_at timestamptz not null default now()
);

create index if not exists approvals_release_idx
  on approvals (release_id, created_at);

create table if not exists audit_events (
  id uuid primary key default gen_random_uuid(),
  org_id text not null,
  actor text not null,
  action text not null,
  subject text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists audit_events_org_idx
  on audit_events (org_id, created_at desc);

create index if not exists audit_events_subject_idx
  on audit_events (subject, created_at);
